<#
.SYNOPSIS
Scans Microsoft 365 for mailbox forwarding, inbox rule forwarding and unusual outbound volume, using metadata only.

.DESCRIPTION
Reads the user list, each mailbox's forwarding settings, each inbox's forwarding rules and the outbound message
trace. It writes JSON and CSV reports, a baseline history and a dashboard.html into the output folder of the
settings file. It does not change anything in the tenant.

A scan that cannot see must not look clean. A single call that fails (the user list, the message trace) stops the
run. A mailbox or inbox that cannot be read is counted and named in summary.json and on the dashboard, and if no
user could be read in a collector the run stops. An account that has no mailbox is not a failure; it is listed
under UsersWithoutMailbox and named on the dashboard. "No mailbox" is not taken on trust: when one collector says
it but the other read that mailbox in the same run, or the last report has forwards for that account that were read
in that run or kept because a read failed, it counts as a failed read; and when a collector says it for every user,
the run stops rather than publish an empty report. Each kept forward records why in KeptBecause (Failed or
NoMailbox). A mailbox that is removed therefore costs one partial run with its forwards kept; when the account says
it has no mailbox again, it is listed under UsersWithoutMailbox and its forwards are dropped, with a line in errors.log.
For a user whose reads failed, the forwards found by the last scan are kept in the report, scored again with the
current settings and exceptions, and marked NotRechecked, so a known forward does not drop off because of one bad
read. A baseline history that cannot be read is left as it is and the run is reported as degraded
(BaselineDegraded in summary.json). A previous report that cannot be read, when it is needed, makes the run fail
closed: every account without a mailbox counts as a failed read, and summary.json sets PreviousReportUnreadable.

The report files are written to hidden temporary files, flushed to the disk, and then swapped into place one by
one, each with an atomic replace, dashboard last. If a swap fails, the files already swapped are put back, so the
output folder holds either the previous run or this one. What an interrupted run left behind is cleaned up at the
start of the next one. Only one scan runs in an output folder at a time: the scan holds output/.scan.lock while it
runs. The scan keeps that file open with no sharing, and the operating system lets go of it when the process ends
in any way, a kill included: a second scan that finds it held stops, and a lock that nobody holds is taken at once.
Only a lock file that cannot be opened for another reason, such as its permissions, is judged by its age, and
replaced once it is more than six hours old.

.PARAMETER SettingsPath
Path to settings.json. A relative path is read from the folder this script is in.

.PARAMETER ApprovedExceptionsPath
Path to the approved exceptions CSV. A missing file means there are no exceptions.

.PARAMETER SkipConnect
Do not sign in to Microsoft Graph and Exchange Online. Used by tests that stub those calls.

.PARAMETER UseDeviceAuthentication
Sign in with a device code instead of a browser window.

.NOTES
Exit codes, so a scheduler can tell the three outcomes apart:
  0  A clean run. Every user was read and the reports were written.
  1  A stopped run. A call failed, no user could be read, a collector found no mailbox for any user, an output file
     could not be replaced, another scan holds the output folder, or the run was stopped part way (Ctrl+C), which
     errors.log records as "Scan did not complete". The report files are left as the previous run wrote them.
  2  A partial scan. The reports were written, but at least one mailbox or inbox could not be read, the outbound
     baseline history could not be read, or the previous report could not be read when it was needed. The dashboard
     has a warning that says which, and summary.json lists the users under CollectionFailures and sets
     BaselineDegraded or PreviousReportUnreadable.
A process that is killed while it swaps files (SIGKILL, a power cut) gets no exit code and cannot put anything back:
the files already swapped stay in place, so the folder can hold some files from that run and the rest from the run
before it until the next scan. Each file is whole, either old or new.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$SettingsPath = "../config/settings.example.json",

    [Parameter()]
    [string]$ApprovedExceptionsPath = "../config/approved-exceptions.example.csv",

    [Parameter()]
    [switch]$SkipConnect,

    [Parameter()]
    [switch]$UseDeviceAuthentication
)

# M365 Forwarding Monitor is metadata-only. It never reads or stores email bodies,
# subjects, previews, attachment contents, or individual message content.
# Detection only: no tenant settings are modified, no rules are deleted, and no forwarding is disabled.

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Starting M365 Forwarding Monitor in metadata-only privacy mode."
Import-Module (Join-Path $scriptRoot "RiskScoring.psm1") -Force
. (Join-Path $scriptRoot "Connect-M365.ps1")
. (Join-Path $scriptRoot "Get-Users.ps1")
. (Join-Path $scriptRoot "Get-ForwardingInventory.ps1")
. (Join-Path $scriptRoot "Get-MessageRuleForwarding.ps1")
. (Join-Path $scriptRoot "Get-OutboundMetadataCounts.ps1")
. (Join-Path $scriptRoot "New-Dashboard.ps1")

function Resolve-M365MonitorPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Resolve-Path -LiteralPath (Join-Path $scriptRoot $Path)).Path
}

function Add-M365Property {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [object]$Value
    )

    if ($InputObject.PSObject.Properties.Name -contains $Name) {
        $InputObject.$Name = $Value
    }
    else {
        $InputObject | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }
}

function Write-M365JsonReport {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [int]$Depth = 8
    )

    # Always a JSON array, so a single item and an empty set read back the same way as any other set.
    # (ConvertTo-Json with the pipeline would turn one item into a bare object and write nothing for none.)
    Write-M365TextFile -Path $Path -Text ((ConvertTo-Json -InputObject @($InputObject) -Depth $Depth) + [Environment]::NewLine)
}

function Read-M365JsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Returns the items in a JSON file this tool wrote: the elements of an array, or the one object of a single-item
    # file from an older version. Throws when the file cannot be read, is empty, or is not complete JSON.
    # ConvertFrom-Json on its own accepts a file that was cut off right after a complete record and returns the
    # records before the cut, so the text goes through the strict System.Text.Json parser first.
    Add-Type -AssemblyName System.Text.Json
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "The file is empty."
    }
    $text = $text.TrimStart([char]0xFEFF)

    try {
        [System.Text.Json.JsonDocument]::Parse($text).Dispose()
    }
    catch {
        throw "The file is not complete JSON: $($_.Exception.GetBaseException().Message)"
    }

    ConvertFrom-Json -InputObject $text
}

function Write-M365CsvFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    # The same text Export-Csv writes, through Write-M365TextFile so it reaches the disk before it is renamed into place.
    $lines = @($InputObject | ConvertTo-Csv -NoTypeInformation)
    $text = if ($lines.Count -gt 0) { ($lines -join [Environment]::NewLine) + [Environment]::NewLine } else { "" }
    Write-M365TextFile -Path $Path -Text $text
}

function Test-M365IsoTimestamp {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    # True for an ISO 8601 date and time, the form the collectors write DetectedAt in. ConvertFrom-Json turns such
    # text into a date, so a date here came from it. Text that is still text must be ISO 8601 itself. A number,
    # true or false, empty text or null is not a time this tool wrote, even where a [datetime] cast would take it.
    if ($Value -is [datetime]) {
        return $true
    }
    if ($Value -isnot [string]) {
        return $false
    }
    $parsed = [datetimeoffset]::MinValue
    return [datetimeoffset]::TryParseExact($Value, [string[]]@("yyyy-MM-ddTHH:mm:ss.FFFFFFFK", "yyyy-MM-ddTHH:mm:ssK"),
        [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)
}

function Read-M365HistoryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Returns the records of an outbound baseline history file. Throws when the file cannot be read, is not complete
    # JSON, or holds anything other than records with an ISO 8601 DetectedAt.
    $records = @(Read-M365JsonFile -Path $Path)
    foreach ($record in $records) {
        if ($record -isnot [System.Management.Automation.PSCustomObject]) {
            throw "It holds a value that is not a history record."
        }
        if ($record.PSObject.Properties.Name -notcontains "DetectedAt" -or -not (Test-M365IsoTimestamp -Value $record.DetectedAt)) {
            throw "It holds a record whose DetectedAt is not an ISO 8601 date and time."
        }
    }
    $records
}

function New-M365RunId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$StartedUtc
    )

    # The run id goes into the names of the run's temporary files and backups. It starts with the UTC time the run
    # started, so the cleanup at the start of a later run can tell which leftovers are older than that run.
    return "{0}-{1}" -f $StartedUtc.ToString("yyyyMMddHHmmssfff", [cultureinfo]::InvariantCulture), [guid]::NewGuid().ToString("N").Substring(0, 8)
}

function Remove-M365File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Deletes one file if it is there, and never a folder. Returns $false only when the file is there but could
    # not be deleted.
    try {
        if ([System.IO.File]::Exists($Path)) {
            [System.IO.File]::Delete($Path)
        }
        return $true
    }
    catch {
        return $false
    }
}

function Move-M365File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    # One rename that replaces the destination in one step: rename(2) on Linux and macOS, an atomic replace on Windows.
    [System.IO.File]::Move($Source, $Destination, $true)
}

function Test-M365TransientFileError {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # True only for a file another program holds for a moment, so that waiting can clear it. The error code decides,
    # never the message: messages are translated, and a path can hold any word.
    #   Windows: ERROR_SHARING_VIOLATION (0x80070020), ERROR_LOCK_VIOLATION (0x80070021), and access denied
    #            (0x80070005), which an indexer, OneDrive or the preview pane causes while it holds a file briefly.
    #   Linux and macOS: EBUSY (16) or ETXTBSY (26), which .NET passes on as the HResult.
    # A path, folder, drive or file that is not there is never tried again.
    for ($exception = $ErrorRecord.Exception; $null -ne $exception; $exception = $exception.InnerException) {
        if ($exception -is [System.IO.FileNotFoundException] -or $exception -is [System.IO.DirectoryNotFoundException] -or
            $exception -is [System.IO.PathTooLongException] -or $exception -is [System.IO.DriveNotFoundException]) {
            return $false
        }
        $code = $exception.HResult
        if ($exception -is [System.UnauthorizedAccessException]) {
            return ($IsWindows -and $code -eq -2147024891)
        }
        if ($exception -is [System.IO.IOException]) {
            return ($code -eq -2147024864 -or $code -eq -2147024863 -or $code -eq 16 -or $code -eq 26 -or ($IsWindows -and $code -eq -2147024891))
        }
    }
    return $false
}

function Move-M365FileWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$Destination
    )

    # On Windows, Excel, an indexer or a sync agent can hold a file for a moment, and a replace fails while it does.
    # A move that fails with a sharing violation is tried three times in all, two seconds apart, before the caller
    # gives up. Any other failure is not tried again.
    for ($attempt = 1; ; $attempt++) {
        try {
            Move-M365File -Source $Source -Destination $Destination
            return
        }
        catch {
            if ($attempt -ge 3 -or -not (Test-M365TransientFileError -ErrorRecord $_)) {
                throw
            }
            Start-Sleep -Seconds 2
        }
    }
}

function Add-M365StagedFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Staged,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$RunId,

        [Parameter(Mandatory)]
        [scriptblock]$Write
    )

    # Writes the new content to a temporary file next to the final path and remembers the pair, with the name the
    # backup of the current file will get. Nothing at the final path changes until Publish-M365StagedFile runs.
    $leaf = Split-Path -Leaf $Path
    $folder = Split-Path -Parent $Path
    $stagedItem = [pscustomobject]@{
        Path       = $Path
        TempPath   = Join-Path $folder (".{0}.{1}.tmp" -f $leaf, $RunId)
        BackupPath = Join-Path $folder (".{0}.{1}.prev" -f $leaf, $RunId)
    }
    $Staged.Add($stagedItem)
    & $Write $stagedItem.TempPath
}

function Publish-M365StagedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Staged
    )

    # Puts the staged files in place in the order they were staged (the dashboard is staged last). If a step fails,
    # the folder is left holding the previous run's files, never a mix.
    #
    # Every destination is checked first, so one that cannot be replaced stops the run before any file changes.
    # A destination must be missing or a plain file that is not read-only. A folder or a link is neither.
    #
    # Then, file by file, the current file is copied to a backup beside it and the temporary file is moved over it
    # in one step: rename(2) on Linux and macOS, an atomic replace on Windows. The name is never missing, not even
    # for a moment, so a program reading the file gets the old one or the new one. The backup is a copy rather than
    # a rename of the current file because a rename would leave the name empty until the new file moved in.
    #
    # If a step fails, or the scan is stopped with Ctrl+C, the files already replaced are put back from their
    # backups, newest first, a file this run created where there was none is removed again, and the temporary files
    # and backups are deleted. A backup that cannot be put back is kept, named in the error and listed in .keep,
    # so later cleanups leave it in place. When every file is in place, the backups are deleted.
    $completed = [System.Collections.Generic.List[object]]::new()
    $notRestored = [System.Collections.Generic.List[object]]::new()
    $current = $null
    $moveFailedItem = $null
    $checking = $true
    $allPlaced = $false
    $failure = $null
    $keepWriteFailed = $false
    try {
        foreach ($item in $Staged) {
            $existing = [System.IO.FileInfo]::new($item.Path)
            if ([int]$existing.Attributes -eq -1) {
                continue
            }
            if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::Directory) -or $null -ne $existing.LinkTarget) {
                throw "Cannot replace the output file $($item.Path): it is a folder or a link, not a plain file. No output files were changed."
            }
            if ($existing.Attributes.HasFlag([System.IO.FileAttributes]::ReadOnly)) {
                throw "Cannot replace the read-only output file $($item.Path). No output files were changed."
            }
        }
        $checking = $false

        foreach ($item in $Staged) {
            $current = $item
            $hasBackup = [System.IO.File]::Exists($item.Path)
            if ($hasBackup) {
                [System.IO.File]::Copy($item.Path, $item.BackupPath, $true)
            }
            # Recorded before the move, so a Ctrl+C that lands right after the move still puts this file back. If the
            # move has not happened, putting the file back from its backup changes nothing.
            $completed.Add([pscustomobject]@{ Item = $item; HasBackup = $hasBackup })
            try {
                Move-M365FileWithRetry -Source $item.TempPath -Destination $item.Path
            }
            catch {
                # The move failed, so this file was not replaced and needs nothing put back.
                $moveFailedItem = $item
                throw
            }
            Write-Verbose "Put $(Split-Path -Leaf $item.Path) in place."
        }
        $allPlaced = $true
    }
    catch {
        $failure = $_
    }
    finally {
        if (-not $allPlaced) {
            for ($index = $completed.Count - 1; $index -ge 0; $index--) {
                $done = $completed[$index]
                if ([object]::ReferenceEquals($done.Item, $moveFailedItem)) {
                    continue
                }
                if ($done.HasBackup) {
                    try {
                        Move-M365FileWithRetry -Source $done.Item.BackupPath -Destination $done.Item.Path
                    }
                    catch {
                        $notRestored.Add($done)
                    }
                }
                elseif (-not (Remove-M365File -Path $done.Item.Path)) {
                    # There was no file here before this run, so putting the folder back means removing it.
                    $notRestored.Add($done)
                }
            }

            $keep = [System.Collections.Generic.List[string]]::new()
            foreach ($item in $Staged) {
                $null = Remove-M365File -Path $item.TempPath
                $kept = @($notRestored | Where-Object { $_.HasBackup -and [object]::ReferenceEquals($_.Item, $item) }).Count -gt 0
                if ($kept) {
                    # The only copy of that file's previous content. .keep tells later cleanups to leave it.
                    $keep.Add((Split-Path -Leaf $item.BackupPath))
                }
                else {
                    $null = Remove-M365File -Path $item.BackupPath
                }
            }
            if ($keep.Count -gt 0) {
                try {
                    [System.IO.File]::AppendAllLines((Join-Path (Split-Path -Parent $Staged[0].Path) ".keep"), [string[]]$keep.ToArray())
                }
                catch {
                    $keepWriteFailed = $true
                }
            }
        }
    }

    if ($null -ne $failure) {
        if ($checking) {
            throw $failure
        }

        $reason = $failure.Exception.GetBaseException().Message.Trim()
        if ($reason -notmatch "[.!?]$") { $reason += "." }
        if ($notRestored.Count -gt 0) {
            $details = foreach ($done in $notRestored) {
                if ($done.HasBackup) {
                    "$($done.Item.Path) could not be put back; its previous content is kept in $(Split-Path -Leaf $done.Item.BackupPath) beside it, which later scans leave in place because .keep lists it"
                }
                else {
                    "$($done.Item.Path) was created by this run and could not be removed"
                }
            }
            $keepNote = if ($keepWriteFailed) { " .keep could not be written, so copy the kept files somewhere else before the next scan." } else { "" }
            throw "Could not put $($current.Path) in place. $reason Some files could not be put back: $($details -join '; '). The other files were put back.$keepNote"
        }
        throw "Could not put $($current.Path) in place. $reason The previous run's files were put back, so the output folder is as it was before this run."
    }

    foreach ($done in $completed) {
        if ($done.HasBackup -and -not (Remove-M365File -Path $done.Item.BackupPath)) {
            Write-Warning "Could not remove the backup $($done.Item.BackupPath). The next scan removes it."
        }
    }
}

function Clear-M365StagedFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Staged
    )

    # Removes only the temporary files this run created and has not yet moved into place.
    foreach ($item in $Staged) {
        if (Test-Path -LiteralPath $item.TempPath -PathType Leaf) {
            Remove-Item -LiteralPath $item.TempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Repair-M365OutputFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$RunId,

        [Parameter(Mandatory)]
        [datetime]$RunStartedUtc
    )

    # Cleans up after a run that stopped part way, for example one that was killed while it put files in place.
    # It runs at the start of a scan, once the scan holds the lock and before it stages anything.
    # A backup (.<file>.<run id>.prev) whose file is missing is put back. When the history is still missing after
    # that, a temporary history (.outbound-baseline-history.json.<run id>.tmp) that reads as a whole history is made
    # the history: an older version deleted the history before it renamed the new one in. A backup listed in .keep
    # is left in place: a failed run could not put it back, and it is the only copy of that file's previous content.
    # Every other temporary file and backup older than this run is deleted. What it does is written to errors.log.
    $historyLeaf = "outbound-baseline-history.json"
    $keepPath = Join-Path $OutputPath ".keep"
    $keepNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    if ([System.IO.File]::Exists($keepPath)) {
        try {
            foreach ($line in [System.IO.File]::ReadAllLines($keepPath)) {
                if (-not [string]::IsNullOrWhiteSpace($line)) { $null = $keepNames.Add($line.Trim()) }
            }
        }
        catch {
            Write-M365MonitorError -Message "Cleanup after an interrupted run: could not read .keep, so no backup was removed this time." -ErrorRecord $_ -OutputPath $OutputPath
            return [pscustomobject]@{ Restored = @(); Removed = @() }
        }
    }

    $pattern = '^\.(?<leaf>.+)\.(?<run>[^.]+)\.(?<kind>tmp|prev)$'
    $leftovers = [System.Collections.Generic.List[object]]::new()
    foreach ($file in @(Get-ChildItem -LiteralPath $OutputPath -File -Force -ErrorAction Stop)) {
        if ($file.Name -notmatch $pattern) {
            continue
        }
        $leaf = $Matches["leaf"]
        $run = $Matches["run"]
        $kind = $Matches["kind"]
        if ($run -eq $RunId) {
            continue
        }

        # A run id starts with the UTC time its run started. A name without one, from an older version, is aged by
        # the time the file was last written.
        $createdUtc = $file.LastWriteTimeUtc
        $stamp = [datetime]::MinValue
        if ($run -match '^(\d{17})-' -and [datetime]::TryParseExact($Matches[1], "yyyyMMddHHmmssfff", [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]"AssumeUniversal, AdjustToUniversal", [ref]$stamp)) {
            $createdUtc = $stamp
        }
        if ($createdUtc -ge $RunStartedUtc) {
            continue
        }
        $leftovers.Add([pscustomobject]@{ File = $file; Leaf = $leaf; Kind = $kind; CreatedUtc = $createdUtc })
    }

    $restored = [System.Collections.Generic.List[string]]::new()
    $kept = [System.Collections.Generic.List[string]]::new()
    $restore = {
        param($Leftover, $Destination)
        try {
            [System.IO.File]::Move($Leftover.File.FullName, $Destination, $false)
            $restored.Add($Leftover.File.Name)
            Write-M365MonitorError -Message "Cleanup after an interrupted run: put back $($Leftover.Leaf) from $($Leftover.File.Name), because $($Leftover.Leaf) was missing." -OutputPath $OutputPath
        }
        catch {
            $kept.Add($Leftover.File.Name)
            Write-M365MonitorError -Message "Cleanup after an interrupted run: could not put back $($Leftover.Leaf) from $($Leftover.File.Name), so it was left in place." -ErrorRecord $_ -OutputPath $OutputPath
        }
    }

    # Newest backup first, so when two interrupted runs left one for the same missing file, the later one wins.
    foreach ($backup in @($leftovers | Where-Object { $_.Kind -eq "prev" } | Sort-Object CreatedUtc -Descending)) {
        $destination = Join-Path $OutputPath $backup.Leaf
        if (-not ([System.IO.File]::Exists($destination) -or [System.IO.Directory]::Exists($destination))) {
            & $restore $backup $destination
        }
    }

    # The history is the one output a run cannot write again from Microsoft 365, so a whole copy of it is not thrown away.
    $historyPath = Join-Path $OutputPath $historyLeaf
    foreach ($temporary in @($leftovers | Where-Object { $_.Kind -eq "tmp" -and $_.Leaf -eq $historyLeaf } | Sort-Object CreatedUtc -Descending)) {
        if ([System.IO.File]::Exists($historyPath) -or [System.IO.Directory]::Exists($historyPath)) {
            break
        }
        try {
            $null = Read-M365HistoryFile -Path $temporary.File.FullName
        }
        catch {
            continue
        }
        & $restore $temporary $historyPath
    }

    $removed = [System.Collections.Generic.List[string]]::new()
    $notRemoved = [System.Collections.Generic.List[string]]::new()
    foreach ($leftover in $leftovers) {
        $name = $leftover.File.Name
        if ($restored.Contains($name) -or $kept.Contains($name)) {
            continue
        }
        if ($keepNames.Contains($name)) {
            Write-M365MonitorError -Message "Cleanup after an interrupted run: kept $name because .keep lists it. It holds the previous content of $($leftover.Leaf), which a failed run could not put back. Delete it and its line in .keep once that is dealt with." -OutputPath $OutputPath
            continue
        }
        if (Remove-M365File -Path $leftover.File.FullName) {
            $removed.Add($name)
        }
        else {
            $notRemoved.Add($name)
        }
    }

    # .keep is only needed while a file it lists is still there.
    if ($keepNames.Count -gt 0 -and @($keepNames | Where-Object { [System.IO.File]::Exists((Join-Path $OutputPath $_)) }).Count -eq 0) {
        $null = Remove-M365File -Path $keepPath
    }

    if ($removed.Count -gt 0) {
        Write-M365MonitorError -Message "Cleanup after an interrupted run: removed $($removed.Count) leftover file(s): $($removed -join ', ')." -OutputPath $OutputPath
    }
    if ($notRemoved.Count -gt 0) {
        Write-M365MonitorError -Message "Cleanup after an interrupted run: could not remove $($notRemoved -join ', ')." -OutputPath $OutputPath
    }

    return [pscustomobject]@{ Restored = @($restored); Removed = @($removed) }
}

function Test-M365LockConflict {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # True when opening the scan lock failed because another process holds it open: on Windows a sharing or lock
    # violation, on Linux and macOS the lock .NET takes on a file opened with no sharing (EWOULDBLOCK, which is 11 on
    # Linux and 35 on macOS). Any other failure, such as access denied, is not a held lock.
    for ($exception = $ErrorRecord.Exception; $null -ne $exception; $exception = $exception.InnerException) {
        if ($exception -is [System.IO.IOException] -and $exception -isnot [System.IO.FileNotFoundException] -and $exception -isnot [System.IO.DirectoryNotFoundException]) {
            $code = $exception.HResult
            if ($code -eq -2147024864 -or $code -eq -2147024863) {
                return $true
            }
            if (-not $IsWindows -and ($code -eq 11 -or $code -eq 35)) {
                return $true
            }
        }
    }
    return $false
}

function ConvertFrom-M365ScanLockText {
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    # What a scan wrote into the lock, for people to read: its process id, its computer and when it started.
    $processId = if ($Text -match '(?m)^ProcessId:\s*(\d+)') { $Matches[1] } else { "unknown" }
    $machineName = if ($Text -match '(?m)^MachineName:[ \t]*(\S.*?)[ \t]*$') { $Matches[1] } else { "an unknown computer" }
    $startedAt = if ($Text -match '(?m)^StartedAt:\s*(\S+)') { $Matches[1] } else { "an unknown time" }
    return [pscustomobject]@{ ProcessId = $processId; MachineName = $machineName; StartedAt = $startedAt }
}


function Enter-M365ScanLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [datetime]$StartedUtc
    )

    # One scan per output folder. The scan opens output/.scan.lock with no sharing and keeps it open until the end.
    # The operating system holds that lock for it and lets go when the process ends in any way, a kill included, so a
    # lock that nobody holds is taken at once, and a scan that finds it held stops. The process id, computer name and
    # start time written into the file are for people to read; they decide nothing.
    # Only when the file cannot be opened for another reason, such as its permissions, is it unknown whether a scan
    # holds it. Then its age decides: under six hours the scan stops, over six hours the file is replaced.
    $lockPath = Join-Path $OutputPath ".scan.lock"
    $staleAfter = [timespan]::FromHours(6)
    $openError = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $stream = $null
        try {
            $stream = [System.IO.FileStream]::new($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch {
            $openError = $_
        }

        if ($null -ne $stream) {
            try {
                $previous = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $false, 1024, $true).ReadToEnd()
                if (-not [string]::IsNullOrWhiteSpace($previous)) {
                    # A scan empties the lock when it ends, so text in it was left by a scan that was killed.
                    $holder = ConvertFrom-M365ScanLockText -Text $previous
                    Write-M365MonitorError -Message "Took over the scan lock in $OutputPath from a scan that started $($holder.StartedAt) (process $($holder.ProcessId) on $($holder.MachineName)): that scan is no longer running, because no process holds the lock." -OutputPath $OutputPath
                }
                $text = "ProcessId: $PID`nMachineName: $([System.Environment]::MachineName)`nStartedAt: $($StartedUtc.ToString('o', [cultureinfo]::InvariantCulture))`n"
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
                $stream.SetLength(0)
                $stream.Position = 0
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            }
            catch {
                $stream.Dispose()
                throw "Could not write the scan lock $lockPath. $($_.Exception.GetBaseException().Message)"
            }
            return [pscustomobject]@{ Path = $lockPath; Stream = $stream; Text = $text; OutputPath = $OutputPath }
        }

        $writtenUtc = [System.IO.File]::GetLastWriteTimeUtc($lockPath)
        $writtenText = $writtenUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", [cultureinfo]::InvariantCulture)
        if (Test-M365LockConflict -ErrorRecord $openError) {
            throw "Another scan is running in $OutputPath (started $writtenText)."
        }

        $reason = $openError.Exception.GetBaseException().Message
        if ($attempt -gt 1 -or -not [System.IO.File]::Exists($lockPath)) {
            throw "Could not open the scan lock $lockPath. $reason"
        }
        if (([datetime]::UtcNow - $writtenUtc) -lt $staleAfter) {
            throw "Another scan may be running in ${OutputPath}: the scan lock $lockPath cannot be opened ($reason), so whether a scan holds it cannot be told. It was last written at $writtenText, less than six hours ago, so this scan did not start. If no scan is running, fix the lock's permissions or delete it."
        }
        try {
            [System.IO.File]::SetAttributes($lockPath, [System.IO.FileAttributes]::Normal)
            [System.IO.File]::Delete($lockPath)
        }
        catch {
            throw "The scan lock $lockPath cannot be opened ($reason) or removed ($($_.Exception.GetBaseException().Message)). Fix its permissions or delete it, then run the scan again."
        }
        Write-M365MonitorError -Message "Took over the scan lock in ${OutputPath}: it could not be opened ($reason) and was last written at $writtenText, more than six hours ago, so it was replaced." -OutputPath $OutputPath
    }

    throw "Could not open the scan lock $lockPath."
}

function Exit-M365ScanLock {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Lock
    )

    # Empties the lock and lets go of it. The file stays: only the lock the operating system holds on it counts, and
    # deleting it could let two scans lock two different files of the same name. This runs in the script's finally
    # block, which Ctrl+C also runs. SIGTERM and kills skip it; the operating system lets go of the lock when the
    # process ends, and the next scan takes it at once.
    if ($null -eq $Lock) {
        return
    }

    try {
        $Lock.Stream.SetLength(0)
        $Lock.Stream.Flush($true)
    }
    catch {
        Write-M365MonitorError -Message "Could not empty the scan lock $($Lock.Path) on the way out, so it still names this scan. No process holds it once this one ends, so the next scan takes it at once." -ErrorRecord $_ -OutputPath $Lock.OutputPath
        Write-Warning "Could not empty the scan lock $($Lock.Path). See errors.log."
    }
    finally {
        $Lock.Stream.Dispose()
    }
}

function Get-M365PreviousFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Reads the forwarding-findings.json the previous run wrote, before this run replaces it. Returns Rows and
    # Unreadable. With neither it nor summary.json there, this is a first run and nothing is wrong. Unreadable means
    # the findings it held cannot be kept, and the caller fails closed: the file cannot be read, is not complete JSON,
    # holds something other than a list of findings (null, a number, an object of another shape), or is missing
    # although summary.json shows that an earlier run completed.
    $result = [pscustomobject]@{ Rows = @(); Unreadable = $false }
    $path = Join-Path $OutputPath "forwarding-findings.json"
    $consequence = "so the last scan's findings could not be kept, and every account reported without a mailbox is counted as a failed read in this run."
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if (Test-Path -LiteralPath (Join-Path $OutputPath "summary.json") -PathType Leaf) {
            $result.Unreadable = $true
            Write-M365MonitorError -Message "The previous forwarding-findings.json is missing although summary.json shows that an earlier run completed, $consequence" -OutputPath $OutputPath
        }
        return $result
    }

    try {
        $rows = @(Read-M365JsonFile -Path $path)
        foreach ($row in $rows) {
            if ($row -isnot [System.Management.Automation.PSCustomObject] -or [string]::IsNullOrWhiteSpace([string]$row.UserPrincipalName) -or
                [string]::IsNullOrWhiteSpace([string]$row.ForwardingType)) {
                throw "It holds something that is not a forwarding finding."
            }
        }
        $result.Rows = $rows
    }
    catch {
        $result.Unreadable = $true
        Write-M365MonitorError -Message "Could not read the previous forwarding-findings.json, $consequence" -ErrorRecord $_ -OutputPath $OutputPath
    }
    return $result
}

function Get-M365KeptBecause {
    param(
        [Parameter(Mandatory)]
        [object]$Row
    )

    # Why a row of an earlier report was there: empty for a forward read in that run, Failed for one kept because a
    # read failed, NoMailbox for one kept because the account said it had no mailbox. A kept row from a version that
    # did not write the reason counts as Failed, so it gets the one-run grace.
    $wasKept = $Row.PSObject.Properties.Name -contains "NotRechecked" -and $Row.NotRechecked -eq $true
    if (-not $wasKept) {
        return ""
    }
    if ($Row.PSObject.Properties.Name -contains "KeptBecause" -and [string]$Row.KeptBecause -eq "NoMailbox") {
        return "NoMailbox"
    }
    return "Failed"
}

function Resolve-M365NoMailboxUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$FailedMailboxUsers,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$NoMailboxUsers,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$FailedRuleUsers,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$NoRuleMailboxUsers,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$PreviousFindings = @(),

        [Parameter()]
        [switch]$PreviousReportUnreadable,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # "No mailbox" means there is nothing to check, so it must not be what a blind read looks like. An account is
    # moved from a collector's no-mailbox list to its failed list, in place, when:
    #   - the other collector read that account's mailbox in this run, so the mailbox is there (kept as Failed);
    #   - the previous report could not be read, so it cannot be told what the account had (kept as NoMailbox); or
    #   - the previous report has a forward for the account that was read in that run, or kept because a read failed
    #     (kept as NoMailbox). That is the one-run grace.
    # A forward kept because of NoMailbox gets no second grace: when the account says it has no mailbox again, the
    # account is listed under UsersWithoutMailbox and those forwards are dropped, with a line in errors.log.
    # Returns the users moved for NoMailbox in each collector, so their kept rows record that reason.
    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $mailboxNotRead = [System.Collections.Generic.HashSet[string]]::new([string[]]@($FailedMailboxUsers + $NoMailboxUsers), $comparer)
    $rulesNotRead = [System.Collections.Generic.HashSet[string]]::new([string[]]@($FailedRuleUsers + $NoRuleMailboxUsers), $comparer)
    $graceUsers = [System.Collections.Generic.HashSet[string]]::new($comparer)
    $previousMailboxUsers = [System.Collections.Generic.HashSet[string]]::new($comparer)
    $previousRuleUsers = [System.Collections.Generic.HashSet[string]]::new($comparer)
    foreach ($row in @($PreviousFindings)) {
        $upn = [string]$row.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn)) { continue }
        if ((Get-M365KeptBecause -Row $row) -ne "NoMailbox") { $null = $graceUsers.Add($upn) }
        if ([string]$row.ForwardingType -eq "MailboxForwarding") { $null = $previousMailboxUsers.Add($upn) } else { $null = $previousRuleUsers.Add($upn) }
    }

    $collectors = @(
        @{ Label = "Mailbox forwarding"; Kind = "mailbox forwarding"; Source = "Get-Mailbox"; Other = "Microsoft Graph read the inbox rules in this run"
            NoMailbox = $NoMailboxUsers; Failed = $FailedMailboxUsers; OtherNotRead = $rulesNotRead; Previous = $previousMailboxUsers
            KeptForNoMailbox = [System.Collections.Generic.HashSet[string]]::new($comparer) }
        @{ Label = "Inbox rules"; Kind = "inbox rules"; Source = "Microsoft Graph"; Other = "Get-Mailbox read the mailbox in this run"
            NoMailbox = $NoRuleMailboxUsers; Failed = $FailedRuleUsers; OtherNotRead = $mailboxNotRead; Previous = $previousRuleUsers
            KeptForNoMailbox = [System.Collections.Generic.HashSet[string]]::new($comparer) }
    )
    foreach ($collector in $collectors) {
        foreach ($upn in @($collector.NoMailbox)) {
            $why = $null
            $forNoMailbox = $true
            if (-not $collector.OtherNotRead.Contains($upn)) {
                $why = $collector.Other
                $forNoMailbox = $false
            }
            elseif ($PreviousReportUnreadable) {
                $why = "the previous report could not be read to tell whether this account had forwards"
            }
            elseif ($graceUsers.Contains($upn)) {
                $why = "the last report has forwards for this account"
            }
            if ($null -eq $why) {
                continue
            }
            $null = $collector.NoMailbox.Remove($upn)
            $collector.Failed.Add($upn)
            if ($forNoMailbox) { $null = $collector.KeptForNoMailbox.Add($upn) }
            Write-M365MonitorError -Message "$($collector.Label) for ${upn}: $($collector.Source) reported no mailbox, but $why, so this is counted as a failed read." -OutputPath $OutputPath
        }
    }

    # What is left on a no-mailbox list with forwards in the last report had them kept because of NoMailbox, so this
    # collector has now said twice that there is no mailbox. Those forwards are not kept again.
    foreach ($collector in $collectors) {
        foreach ($upn in @($collector.NoMailbox)) {
            if ($collector.Previous.Contains($upn)) {
                Write-M365MonitorError -Message "Dropped the earlier forwards for $upn ($($collector.Kind)): $($collector.Source) has reported no mailbox for two runs, so the findings kept from before were removed from the report." -OutputPath $OutputPath
            }
        }
    }

    return [pscustomobject]@{
        MailboxKeptForNoMailbox = @($collectors[0].KeptForNoMailbox)
        RuleKeptForNoMailbox    = @($collectors[1].KeptForNoMailbox)
    }
}

function Get-M365CarriedFinding {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$PreviousFindings = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$MailboxFailedUsers = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$RuleFailedUsers = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$MailboxKeptForNoMailbox = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$RuleKeptForNoMailbox = @(),

        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ApprovedExceptions = @()
    )

    # Returns the rows of the previous report for users whose reads failed in this run, so a known forward does not
    # drop off the report because of one bad read. Each collector decides for its own rows: a failed mailbox read
    # keeps the user's mailbox forwarding rows, a failed inbox rule read keeps the user's inbox rule rows, and what
    # this run did read replaces the rest. Each kept row is marked NotRechecked, keeps the DetectedAt of the scan that
    # found it, and records in KeptBecause why it was kept: NoMailbox when the failure was a "no mailbox" answer
    # counted as a failed read, Failed otherwise.
    #
    # The forward itself was not read again, but the rules it is judged by are this run's: IsExternal,
    # IsPersonalDomain, ApprovedException and RiskLevel are worked out again from ForwardTarget with the current
    # settings and exceptions, so an expired exception or a changed domain list counts at once.
    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $mailboxFailed = [System.Collections.Generic.HashSet[string]]::new([string[]]@($MailboxFailedUsers), $comparer)
    $ruleFailed = [System.Collections.Generic.HashSet[string]]::new([string[]]@($RuleFailedUsers), $comparer)
    $mailboxForNoMailbox = [System.Collections.Generic.HashSet[string]]::new([string[]]@($MailboxKeptForNoMailbox), $comparer)
    $ruleForNoMailbox = [System.Collections.Generic.HashSet[string]]::new([string[]]@($RuleKeptForNoMailbox), $comparer)
    if ($mailboxFailed.Count -eq 0 -and $ruleFailed.Count -eq 0) {
        return
    }

    foreach ($row in @($PreviousFindings)) {
        if ($row -isnot [System.Management.Automation.PSCustomObject]) {
            continue
        }
        $upn = [string]$row.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn)) {
            continue
        }
        # Plain assignments: an if expression would send the set down the pipeline and hand back its items.
        $isMailboxRow = [string]$row.ForwardingType -eq "MailboxForwarding"
        $failedUsers = $ruleFailed
        $forNoMailbox = $ruleForNoMailbox
        if ($isMailboxRow) {
            $failedUsers = $mailboxFailed
            $forNoMailbox = $mailboxForNoMailbox
        }
        if (-not $failedUsers.Contains($upn)) {
            continue
        }

        # ConvertFrom-Json turns the ISO 8601 text into a date. Write it back in the form the collectors use.
        if ($row.DetectedAt -is [datetime]) {
            $row.DetectedAt = $row.DetectedAt.ToString("o", [cultureinfo]::InvariantCulture)
        }

        $target = [string]$row.ForwardTarget
        $domain = Get-M365TargetDomain -Target $target
        $isExternal = -not (Test-M365InternalDomain -Domain $domain -InternalDomains $Settings.InternalDomains)
        $isPersonal = Test-M365PersonalDomain -Domain $domain -PersonalDomains $Settings.PersonalDomains
        $approved = Test-M365ApprovedException -UserPrincipalName $upn -Target $target -ApprovedExceptions $ApprovedExceptions
        $enabled = $true
        if (-not $isMailboxRow -and $row.PSObject.Properties.Name -contains "RuleEnabled" -and $null -ne $row.RuleEnabled) {
            $enabled = [bool]$row.RuleEnabled
        }
        Add-M365Property -InputObject $row -Name "TargetDomain" -Value $domain
        Add-M365Property -InputObject $row -Name "IsExternal" -Value ([bool]$isExternal)
        Add-M365Property -InputObject $row -Name "IsPersonalDomain" -Value ([bool]$isPersonal)
        Add-M365Property -InputObject $row -Name "ApprovedException" -Value ([bool]$approved)
        Add-M365Property -InputObject $row -Name "RiskLevel" -Value (Get-M365ForwardingRiskLevel -RuleEnabled $enabled -IsExternal $isExternal -IsPersonalDomain $isPersonal -ApprovedException $approved)
        Add-M365Property -InputObject $row -Name "NotRechecked" -Value $true
        Add-M365Property -InputObject $row -Name "KeptBecause" -Value $(if ($forNoMailbox.Contains($upn)) { "NoMailbox" } else { "Failed" })
        $row
    }
}

function Update-M365OutboundBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$OutboundCounts,

        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Returns Records, the history records to write, and HistoryUnreadable. The caller stages Records with the other
    # output files unless HistoryUnreadable is set: a history file that is there but cannot be read or parsed (locked,
    # cut short, empty, a record without an ISO 8601 DetectedAt) is left exactly as it is, because writing this run's
    # records over it would replace weeks of baseline with one day. The baselines in that run start from no history,
    # and the caller reports the run as degraded.
    # Metadata-only baseline: stores sender, counts, domains, and timestamps only.
    # It does not store email subjects, bodies, previews, attachments, or message content.
    $historyPath = Join-Path $OutputPath "outbound-baseline-history.json"
    $history = @()
    $historyUnreadable = $false
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $history = @(Read-M365HistoryFile -Path $historyPath)
        }
        catch {
            Write-M365MonitorError -Message "Could not read outbound baseline history $historyPath, so it was left as it is and this run did not add to it. Baselines in this run start from no history. Repair or move the file so the next run can write it." -ErrorRecord $_ -OutputPath $OutputPath
            $history = @()
            $historyUnreadable = $true
        }
    }

    $multiplier = if ($Settings.PSObject.Properties.Name -contains "BaselineMultiplier") { [double]$Settings.BaselineMultiplier } else { 2.5 }
    $minimumSamples = if ($Settings.PSObject.Properties.Name -contains "BaselineMinimumSamples") { [int]$Settings.BaselineMinimumSamples } else { 3 }
    # A retention of zero days or less would drop the whole history on the next write, so it falls back to 90.
    $retentionDays = 90
    if ($Settings.PSObject.Properties.Name -contains "BaselineRetentionDays") {
        $configuredDays = [int]$Settings.BaselineRetentionDays
        if ($configuredDays -gt 0) {
            $retentionDays = $configuredDays
        }
        else {
            Write-M365MonitorError -Message "BaselineRetentionDays is $configuredDays, which would drop the whole baseline history. Using the default of 90 days." -OutputPath $OutputPath
            Write-Warning "BaselineRetentionDays is $configuredDays. Using the default of 90 days."
        }
    }
    $cutoff = (Get-Date).AddDays(-1 * $retentionDays)

    $currentRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $OutboundCounts) {
        $senderAddress = [string]$row.SenderAddress
        $prior = @($history | Where-Object {
            $_.SenderAddress -eq $senderAddress -and
            $_.ExternalSentCount -ne $null -and
            ([datetime]$_.DetectedAt) -ge $cutoff
        })

        $baselineAverage = $null
        if ($prior.Count -gt 0) {
            $baselineAverage = [Math]::Round((($prior | Measure-Object -Property ExternalSentCount -Average).Average), 2)
        }

        $delta = if ($null -ne $baselineAverage) { [Math]::Round(([double]$row.ExternalSentCount - [double]$baselineAverage), 2) } else { $null }
        $isAboveBaseline = $false
        if ($prior.Count -ge $minimumSamples -and $baselineAverage -gt 0) {
            $isAboveBaseline = [double]$row.ExternalSentCount -ge ([double]$baselineAverage * $multiplier)
        }

        Add-M365Property -InputObject $row -Name "BaselineAverage" -Value $baselineAverage
        Add-M365Property -InputObject $row -Name "BaselineSampleCount" -Value $prior.Count
        Add-M365Property -InputObject $row -Name "BaselineMultiplier" -Value $multiplier
        Add-M365Property -InputObject $row -Name "IsAboveBaseline" -Value $isAboveBaseline
        Add-M365Property -InputObject $row -Name "CountDeltaFromBaseline" -Value $delta
        Add-M365Property -InputObject $row -Name "RiskLevel" -Value (Get-M365OutboundRiskLevel -ExternalSentCount ([int]$row.ExternalSentCount) -AfterHoursCount ([int]$row.AfterHoursCount) -BaselineAverage $baselineAverage -BaselineSampleCount $prior.Count -IsAboveBaseline $isAboveBaseline -Settings $Settings)

        $currentRecords.Add([pscustomobject]@{
            Date                         = $row.Date
            SenderAddress                = $row.SenderAddress
            ExternalSentCount            = $row.ExternalSentCount
            UniqueExternalRecipientCount = $row.UniqueExternalRecipientCount
            TopExternalDomains           = $row.TopExternalDomains
            AfterHoursCount              = $row.AfterHoursCount
            DetectedAt                   = $row.DetectedAt
        })
    }

    $retainedHistory = @($history | Where-Object {
        $_.DetectedAt -and ([datetime]$_.DetectedAt) -ge $cutoff
    })
    return [pscustomobject]@{
        Records           = @($retainedHistory + $currentRecords)
        HistoryUnreadable = $historyUnreadable
    }
}

$settingsFile = Resolve-M365MonitorPath -Path $SettingsPath
$settings = Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
if ($settings.PrivacyMode -ne $true) {
    throw "PrivacyMode must be true. This tool is designed for metadata-only operation."
}

$outputPath = $settings.OutputPath
if (-not [System.IO.Path]::IsPathRooted($outputPath)) {
    $repoRoot = Split-Path -Parent $scriptRoot
    $outputPath = Join-Path $repoRoot $outputPath
}
if (-not (Test-Path -LiteralPath $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

$approvedExceptions = @()
$exceptionPathCandidate = if ([System.IO.Path]::IsPathRooted($ApprovedExceptionsPath)) {
    $ApprovedExceptionsPath
}
else {
    Join-Path $scriptRoot $ApprovedExceptionsPath
}
if (Test-Path -LiteralPath $exceptionPathCandidate) {
    $approvedExceptions = @(Import-Csv -LiteralPath $exceptionPathCandidate)
}

# Every file the run writes is staged first, then put in place one by one with the dashboard last. If anything
# fails before or while they are put in place, the previous run's files are left or put back as they were.
$runStartedUtc = [datetime]::UtcNow
$runId = New-M365RunId -StartedUtc $runStartedUtc
$stagedFiles = [System.Collections.Generic.List[object]]::new()
$scanLock = $null
# Set only when the run gets to the end, or when it stops on an error (which exits 1 on its own). A run that is
# stopped part way, for example with Ctrl+C, has neither, and the finally block below makes it exit 1.
$script:runCompleted = $false
$script:runFailed = $false
$script:filesPublished = $false

try {
    # One scan per output folder. A second scan stops here, before it reads or writes anything else.
    $scanLock = Enter-M365ScanLock -OutputPath $outputPath -StartedUtc $runStartedUtc
    $cleanup = Repair-M365OutputFolder -OutputPath $outputPath -RunId $runId -RunStartedUtc $runStartedUtc
    if ($cleanup.Restored.Count -gt 0 -or $cleanup.Removed.Count -gt 0) {
        Write-Host "Cleaned up after an interrupted run: put back $($cleanup.Restored.Count) file(s) and removed $($cleanup.Removed.Count) leftover file(s). See errors.log."
    }

    # Settings problems fail here, before sign-in and before any collector runs. An unknown business time
    # zone would otherwise surface only after the user list and every mailbox had been read.
    $null = Get-M365BusinessHoursTimeZone -Settings $settings

    # An approved exception whose ExpirationDate is not yyyy-MM-dd approves nothing. Say so once per run,
    # so a forward that turns Critical after a spreadsheet re-save has an explanation in errors.log.
    foreach ($exception in $approvedExceptions) {
        if ((Get-M365ExceptionExpiry -Exception $exception).State -eq "Unreadable") {
            $rawExpiry = ([string]$exception.ExpirationDate) -replace "[\r\n]+", " "
            Write-M365MonitorError -Message "Approved exception skipped: ExpirationDate '$rawExpiry' is not in the form yyyy-MM-dd, so it approves nothing. User: $($exception.UserPrincipalName). Approved target: $($exception.ApprovedTarget)." -OutputPath $outputPath
        }
    }

    if (-not $SkipConnect) {
        Connect-M365Monitor -Settings $settings -OutputPath $outputPath -UseDeviceAuthentication:$UseDeviceAuthentication
    }

    Write-Host "Collecting user list..."
    $users = @(Get-M365MonitorUsers -OutputPath $outputPath)
    if ($users.Count -eq 0) {
        throw "No users were returned from Microsoft Graph. Check Graph authentication and permissions: User.Read.All and MailboxSettings.Read."
    }
    $scannableUserCount = @($users | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.UserPrincipalName) }).Count

    # A scan that cannot see must not report all clear. Users the collectors could not read are counted and
    # reported, and if a collector could not read any user the run stops before any output file changes.
    # A collector that sees no mailbox for anyone stops the run like a collector that could read nobody, rather than
    # publish a report with nothing in it. For Exchange that usually means the session is in another tenant or cannot
    # see the recipients. Graph always reads its own tenant, so there it means no account has a mailbox Graph reaches.
    $blindMessage = "The session is probably signed in to the wrong tenant, or the account lacks recipient scope for these mailboxes. No output files were changed. Check TenantId and ExchangeOrganization in settings.json and the account's roles."
    $graphBlindMessage = "No scanned account has a mailbox reachable through Graph, which usually means they are all unlicensed or on-premises. The scan stopped rather than publish an empty report. No output files were changed."

    Write-Host "Scanning mailbox-level forwarding..."
    $failedMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $noMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $mailboxForwarding = @(Get-M365ForwardingInventory -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedMailboxUsers -NoMailboxUsers $noMailboxUsers)
    if ($failedMailboxUsers.Count -gt 0 -and ($failedMailboxUsers.Count + $noMailboxUsers.Count) -ge $scannableUserCount) {
        throw "Mailbox forwarding could not be read for any scanned user ($($failedMailboxUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }
    if ($scannableUserCount -gt 0 -and $noMailboxUsers.Count -ge $scannableUserCount) {
        throw "Exchange Online reported no mailbox for any of the $scannableUserCount scanned users. $blindMessage"
    }

    Write-Host "Scanning inbox forwarding rules..."
    $failedRuleUsers = [System.Collections.Generic.List[string]]::new()
    $noRuleMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $ruleForwarding = @(Get-M365MessageRuleForwarding -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedRuleUsers -NoMailboxUsers $noRuleMailboxUsers)
    if ($failedRuleUsers.Count -gt 0 -and ($failedRuleUsers.Count + $noRuleMailboxUsers.Count) -ge $scannableUserCount) {
        throw "Inbox rules could not be read for any scanned user ($($failedRuleUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }
    if ($scannableUserCount -gt 0 -and $noRuleMailboxUsers.Count -ge $scannableUserCount) {
        throw "Microsoft Graph reported no mailbox for any of the $scannableUserCount scanned users. $graphBlindMessage"
    }

    # An account one collector says has no mailbox is a failed read when the other collector read its mailbox, or
    # when the last report has forwards for it. The previous report is read once, before it is replaced.
    # It is only needed when someone failed or has no mailbox; when it cannot be read then, the run fails closed:
    # every account without a mailbox counts as a failed read, and summary.json says PreviousReportUnreadable.
    $previousFindings = @()
    $previousReportUnreadable = $false
    if (($failedMailboxUsers.Count + $noMailboxUsers.Count + $failedRuleUsers.Count + $noRuleMailboxUsers.Count) -gt 0) {
        $previousReport = Get-M365PreviousFinding -OutputPath $outputPath
        $previousFindings = @($previousReport.Rows)
        $previousReportUnreadable = [bool]$previousReport.Unreadable
    }
    $resolved = Resolve-M365NoMailboxUser -FailedMailboxUsers $failedMailboxUsers -NoMailboxUsers $noMailboxUsers -FailedRuleUsers $failedRuleUsers `
        -NoRuleMailboxUsers $noRuleMailboxUsers -PreviousFindings $previousFindings -PreviousReportUnreadable:$previousReportUnreadable -OutputPath $outputPath

    # Every finding read in this run was checked in this run. For a user whose reads failed, the last scan's
    # findings are kept, scored again with this run's settings and marked, so a known forward does not drop off
    # the report because of one bad read.
    foreach ($finding in @($mailboxForwarding + $ruleForwarding)) {
        Add-M365Property -InputObject $finding -Name "NotRechecked" -Value $false
        Add-M365Property -InputObject $finding -Name "KeptBecause" -Value ""
    }
    $usersWithoutMailbox = @($noMailboxUsers + $noRuleMailboxUsers | Select-Object -Unique)
    $carriedFindings = @(Get-M365CarriedFinding -PreviousFindings $previousFindings -MailboxFailedUsers $failedMailboxUsers -RuleFailedUsers $failedRuleUsers `
            -MailboxKeptForNoMailbox $resolved.MailboxKeptForNoMailbox -RuleKeptForNoMailbox $resolved.RuleKeptForNoMailbox -Settings $settings -ApprovedExceptions $approvedExceptions)
    if ($carriedFindings.Count -gt 0) {
        $mailboxForwarding = @($mailboxForwarding + @($carriedFindings | Where-Object { $_.ForwardingType -eq "MailboxForwarding" }))
        $ruleForwarding = @($ruleForwarding + @($carriedFindings | Where-Object { $_.ForwardingType -ne "MailboxForwarding" }))
        Write-Host "Kept $($carriedFindings.Count) finding(s) from the last scan for users whose reads failed. They are marked not re-checked."
    }

    Write-Host "Collecting outbound metadata counts..."
    $traceStatus = @{ RowCount = 0; Truncated = $false }
    $outboundCounts = @(Get-M365OutboundMetadataCounts -Settings $settings -OutputPath $outputPath -TraceStatus $traceStatus)
    Write-Host "Updating outbound metadata baseline..."
    $baseline = Update-M365OutboundBaseline -OutboundCounts $outboundCounts -Settings $settings -OutputPath $outputPath
    $baselineHistory = $baseline.Records
    $allForwarding = @($mailboxForwarding + $ruleForwarding)

    $summary = [pscustomobject]@{
        GeneratedAt                       = (Get-Date).ToString("o")
        PrivacyMode                       = $true
        TotalUsersScanned                 = $users.Count
        UsersWithMailboxForwarding        = @($mailboxForwarding.UserPrincipalName | Select-Object -Unique).Count
        UsersWithInboxRuleForwarding      = @($ruleForwarding.UserPrincipalName | Select-Object -Unique).Count
        ExternalForwardingCount           = @($allForwarding | Where-Object { $_.IsExternal }).Count
        PersonalDomainForwardingCount     = @($allForwarding | Where-Object { $_.IsPersonalDomain }).Count
        ApprovedExceptionsCount           = @($allForwarding | Where-Object { $_.ApprovedException }).Count
        HighCriticalRiskCount             = @($allForwarding | Where-Object { $_.RiskLevel -in @("High", "Critical") }).Count
        AbnormalOutboundCount             = @($outboundCounts | Where-Object { $_.RiskLevel -in @("Medium", "Critical") }).Count
        AboveBaselineOutboundCount        = @($outboundCounts | Where-Object { $_.IsAboveBaseline }).Count
        TraceTruncated                    = [bool]$traceStatus.Truncated
        BaselineDegraded                  = [bool]$baseline.HistoryUnreadable
        PreviousReportUnreadable          = $previousReportUnreadable
        UsersWithoutMailbox               = [pscustomobject]@{
            Count              = $usersWithoutMailbox.Count
            UserPrincipalNames = $usersWithoutMailbox
        }
        CollectionFailures                = [pscustomobject]@{
            MailboxForwarding = [pscustomobject]@{ Count = $failedMailboxUsers.Count; UserPrincipalNames = @($failedMailboxUsers) }
            InboxRules        = [pscustomobject]@{ Count = $failedRuleUsers.Count; UserPrincipalNames = @($failedRuleUsers) }
        }
    }

    # CSV only: text fields such as rule names, display names and forwarding targets are set by users
    # or by outside senders, so each string goes through ConvertTo-M365CsvSafeValue. The JSON keeps raw values.
    # One fixed column set for both kinds of finding, so the header does not depend on which kind comes first.
    # Columns shared by both come first, then the mailbox-only column, then the inbox-rule columns.
    $findingColumns = @(
        "UserPrincipalName", "DisplayName", "ForwardingType", "ForwardTarget", "TargetDomain", "IsExternal",
        "IsPersonalDomain", "ApprovedException", "RiskLevel", "DetectedAt",
        "DeliverToMailboxAndForward", "RuleName", "RuleId", "RuleEnabled", "NotRechecked", "KeptBecause"
    )

    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "forwarding-findings.json") -Write {
        param($TempPath)
        Write-M365JsonReport -InputObject $allForwarding -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "outbound-metadata-counts.json") -Write {
        param($TempPath)
        Write-M365JsonReport -InputObject $outboundCounts -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "summary.json") -Write {
        param($TempPath)
        Write-M365TextFile -Path $TempPath -Text (($summary | ConvertTo-Json -Depth 5) + [Environment]::NewLine)
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "forwarding-findings.csv") -Write {
        param($TempPath)
        $rows = @($allForwarding |
                ForEach-Object {
                    $csvRow = $_.PSObject.Copy()
                    foreach ($property in $csvRow.PSObject.Properties) {
                        if ($property.Value -is [string]) { $property.Value = ConvertTo-M365CsvSafeValue $property.Value }
                    }
                    $csvRow
                } |
                Select-Object -Property $findingColumns)
        Write-M365CsvFile -InputObject $rows -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "outbound-metadata-counts.csv") -Write {
        param($TempPath)
        $rows = @($outboundCounts |
                Select-Object Date,
                    @{ Name = "UserPrincipalName"; Expression = { ConvertTo-M365CsvSafeValue $_.UserPrincipalName } },
                    @{ Name = "SenderAddress"; Expression = { ConvertTo-M365CsvSafeValue $_.SenderAddress } },
                    ExternalSentCount, UniqueExternalRecipientCount,
                    @{ Name = "TopExternalDomains"; Expression = { ConvertTo-M365CsvSafeValue $_.TopExternalDomains } },
                    AfterHoursCount, BaselineAverage, BaselineSampleCount, BaselineMultiplier, IsAboveBaseline, CountDeltaFromBaseline, RiskLevel, DetectedAt)
        Write-M365CsvFile -InputObject $rows -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "summary.csv") -Write {
        param($TempPath)
        # One flat row: the failure lists stay in summary.json, the CSV carries their counts.
        $rows = @($summary |
                Select-Object -Property * -ExcludeProperty CollectionFailures, UsersWithoutMailbox |
                Select-Object -Property *,
                    @{ Name = "UsersWithoutMailbox"; Expression = { $summary.UsersWithoutMailbox.Count } },
                    @{ Name = "MailboxForwardingFailures"; Expression = { $summary.CollectionFailures.MailboxForwarding.Count } },
                    @{ Name = "InboxRuleFailures"; Expression = { $summary.CollectionFailures.InboxRules.Count } })
        Write-M365CsvFile -InputObject $rows -Path $TempPath
    }
    if ($baseline.HistoryUnreadable) {
        Write-Host "The outbound baseline history could not be read, so this run left it as it is. See errors.log."
    }
    else {
        Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "outbound-baseline-history.json") -Write {
            param($TempPath)
            Write-M365JsonReport -InputObject $baselineHistory -Path $TempPath
        }
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "dashboard.html") -Write {
        param($TempPath)
        $null = New-M365ForwardingDashboard -Summary $summary -ForwardingFindings $allForwarding -OutboundCounts $outboundCounts -OutputPath $outputPath -FilePath $TempPath
    }

    Publish-M365StagedFile -Staged $stagedFiles
    $script:filesPublished = $true
    $dashboard = Join-Path $outputPath "dashboard.html"

    Write-Host ""
    Write-Host "M365 Forwarding Monitor complete. Metadata-only privacy mode is enabled."
    Write-Host "Users scanned: $($summary.TotalUsersScanned)"
    Write-Host "Mailbox forwarding users: $($summary.UsersWithMailboxForwarding)"
    Write-Host "Inbox-rule forwarding users: $($summary.UsersWithInboxRuleForwarding)"
    Write-Host "External forwarding findings: $($summary.ExternalForwardingCount)"
    Write-Host "High/Critical forwarding risks: $($summary.HighCriticalRiskCount)"
    Write-Host "Abnormal outbound metadata rows: $($summary.AbnormalOutboundCount)"
    if ($failedMailboxUsers.Count -gt 0 -or $failedRuleUsers.Count -gt 0 -or $traceStatus.Truncated -or $baseline.HistoryUnreadable -or $previousReportUnreadable) {
        Write-Host "INCOMPLETE SCAN: mailbox read failures $($failedMailboxUsers.Count), inbox rule read failures $($failedRuleUsers.Count), message trace truncated $($traceStatus.Truncated), baseline history unreadable $([bool]$baseline.HistoryUnreadable), previous report unreadable $previousReportUnreadable. See the dashboard and errors.log."
    }
    Write-Host "Dashboard: $dashboard"
    $isPartialScan = $failedMailboxUsers.Count -gt 0 -or $failedRuleUsers.Count -gt 0 -or $baseline.HistoryUnreadable -or $previousReportUnreadable
    $script:runCompleted = $true
}
catch {
    $script:runFailed = $true
    Write-M365MonitorError -Message "Invoke-ForwardingMonitor failed." -ErrorRecord $_ -OutputPath $outputPath
    throw
}
finally {
    # Deletes this run's temporary files that were not put in place, then lets the next scan in. Ctrl+C runs this
    # too, after the put-back in Publish-M365StagedFile. SIGTERM and kills skip it; the next scan on this computer
    # sees that the process which wrote the lock is gone and takes the lock over.
    Clear-M365StagedFile -Staged $stagedFiles
    Exit-M365ScanLock -Lock $scanLock
    if (-not $script:runCompleted -and -not $script:runFailed) {
        $state = if ($script:filesPublished) {
            "after this run's files were put in place, so the report files are this run's"
        }
        else {
            "before this run's files were put in place, and the previous run's files were left or put back as they were"
        }
        Write-M365MonitorError -Message "Scan did not complete. It was stopped, for example with Ctrl+C, $state." -OutputPath $outputPath
        # An exit inside the finally block of a script that is being stopped does not reach the process exit code
        # under pwsh -File; telling the host to exit with 1 does.
        $host.SetShouldExit(1)
        exit 1
    }
}

# 0 clean run, 1 stopped run (the catch above rethrows, and a run stopped part way exits 1 in the finally block),
# 2 partial scan: the reports are written but some users, the baseline history or the previous report could not be read.
if ($isPartialScan) { exit 2 }
