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
under UsersWithoutMailbox. For a user whose reads failed, the forwards found by the last scan are kept in the
report and marked NotRechecked, so a known forward does not drop off because of one bad read.

The report files are written to hidden temporary files first and then swapped into place one by one, each with an
atomic replace, dashboard last. If a swap fails, the files already swapped are put back, so the output folder holds
either the previous run or this one. What an interrupted run left behind is cleaned up at the start of the next one,
and only one scan runs in an output folder at a time: the scan holds output/.scan.lock while it runs.

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
  1  A stopped run. A call failed, no user could be read, an output file could not be replaced, or another scan
     holds the output folder. An error is thrown and the report files are left as the previous run wrote them.
  2  A partial scan. The reports were written, but at least one mailbox or inbox could not be read. The
     dashboard has a warning that names the users, and summary.json lists them under CollectionFailures.
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
    Set-Content -LiteralPath $Path -Value (ConvertTo-Json -InputObject @($InputObject) -Depth $Depth) -Encoding UTF8
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

    # Puts the staged files in place in the order they were staged (the dashboard is staged last). A failed swap
    # puts the files already swapped back, so a failed run leaves the previous run's set intact. A process killed
    # in the middle of the swaps leaves every file whole, old or new, and the next run's sweep removes the copies.
    #
    # Every destination is checked first, so one that cannot be replaced stops the run before any file changes.
    # A destination must be missing or a plain file that is not read-only. A folder or a link is neither.
    #
    # Then, file by file, the current file is copied to a backup beside it and the temporary file is moved over it
    # in one step: rename(2) on Linux and macOS, an atomic replace on Windows. The name is never missing, not even
    # for a moment, so a program reading the file gets the old one or the new one. The backup is a copy rather than
    # a rename of the current file because a rename would leave the name empty until the new file moved in.
    #
    # If a step fails, the files already replaced are put back from their backups, newest first, a file this run
    # created where there was none is removed again, and the temporary files and backups are deleted. When every
    # file is in place, the backups are deleted.
    $completed = [System.Collections.Generic.List[object]]::new()
    $notRestored = [System.Collections.Generic.List[string]]::new()
    $current = $null
    $checking = $true
    $failure = $null
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
            [System.IO.File]::Move($item.TempPath, $item.Path, $true)
            $completed.Add([pscustomobject]@{ Item = $item; HasBackup = $hasBackup })
            Write-Verbose "Put $(Split-Path -Leaf $item.Path) in place."
        }
    }
    catch {
        $failure = $_
    }
    finally {
        # Also runs when the scan is stopped with Ctrl+C part way through, which the catch above does not see.
        if ($completed.Count -lt $Staged.Count) {
            for ($index = $completed.Count - 1; $index -ge 0; $index--) {
                $done = $completed[$index]
                try {
                    if ($done.HasBackup) {
                        [System.IO.File]::Move($done.Item.BackupPath, $done.Item.Path, $true)
                    }
                    else {
                        # There was no file here before this run, so putting the folder back means removing it.
                        [System.IO.File]::Delete($done.Item.Path)
                    }
                }
                catch {
                    $notRestored.Add($done.Item.Path)
                }
            }

            foreach ($item in $Staged) {
                $null = Remove-M365File -Path $item.TempPath
                # A backup that could not be put back is the only copy of that file's previous content, so it stays.
                if (-not $notRestored.Contains($item.Path)) {
                    $null = Remove-M365File -Path $item.BackupPath
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
            throw "Could not put $($current.Path) in place. $reason These files could not be put back and may hold this run's content: $($notRestored -join ', '). The previous content of each is in the .prev file beside it; copy it out before the next scan, which removes leftovers."
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
    # A backup (.<file>.<run id>.prev) whose file is missing is put back. Every other temporary file
    # (.<file>.<run id>.tmp) and backup older than this run is deleted. What it does is written to errors.log.
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

    # Newest backup first, so when two interrupted runs left one for the same missing file, the later one wins.
    $restored = [System.Collections.Generic.List[string]]::new()
    $kept = [System.Collections.Generic.List[string]]::new()
    foreach ($backup in @($leftovers | Where-Object { $_.Kind -eq "prev" } | Sort-Object CreatedUtc -Descending)) {
        $destination = Join-Path $OutputPath $backup.Leaf
        if ([System.IO.File]::Exists($destination) -or [System.IO.Directory]::Exists($destination)) {
            continue
        }
        try {
            [System.IO.File]::Move($backup.File.FullName, $destination, $false)
            $restored.Add($backup.File.Name)
            Write-M365MonitorError -Message "Cleanup after an interrupted run: put back $($backup.Leaf) from $($backup.File.Name), because $($backup.Leaf) was missing." -OutputPath $OutputPath
        }
        catch {
            $kept.Add($backup.File.Name)
            Write-M365MonitorError -Message "Cleanup after an interrupted run: could not put back $($backup.Leaf) from $($backup.File.Name), so the backup was left in place." -ErrorRecord $_ -OutputPath $OutputPath
        }
    }

    $removed = [System.Collections.Generic.List[string]]::new()
    $notRemoved = [System.Collections.Generic.List[string]]::new()
    foreach ($leftover in $leftovers) {
        $name = $leftover.File.Name
        if ($restored.Contains($name) -or $kept.Contains($name)) {
            continue
        }
        if (Remove-M365File -Path $leftover.File.FullName) {
            $removed.Add($name)
        }
        else {
            $notRemoved.Add($name)
        }
    }

    if ($removed.Count -gt 0) {
        Write-M365MonitorError -Message "Cleanup after an interrupted run: removed $($removed.Count) leftover file(s): $($removed -join ', ')." -OutputPath $OutputPath
    }
    if ($notRemoved.Count -gt 0) {
        Write-M365MonitorError -Message "Cleanup after an interrupted run: could not remove $($notRemoved -join ', ')." -OutputPath $OutputPath
    }

    return [pscustomobject]@{ Restored = @($restored); Removed = @($removed) }
}

function Read-M365ScanLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Returns what a scan lock says, or $null when there is no lock file. A start time that cannot be read is taken
    # from the time the file was last written, so a lock left empty by a scan that stopped at the wrong moment
    # still ages out.
    if (-not [System.IO.File]::Exists($Path)) {
        return $null
    }

    $text = ""
    try {
        $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]"ReadWrite, Delete")
        try {
            $text = [System.IO.StreamReader]::new($stream).ReadToEnd()
        }
        finally {
            $stream.Dispose()
        }
    }
    catch {
        if (-not [System.IO.File]::Exists($Path)) {
            return $null
        }
    }

    $startedUtc = $null
    $parsed = [datetimeoffset]::MinValue
    if ($text -match '(?m)^StartedAt:\s*(\S+)' -and
        [datetimeoffset]::TryParse($Matches[1], [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        $startedUtc = $parsed.UtcDateTime
    }
    else {
        $startedUtc = [System.IO.File]::GetLastWriteTimeUtc($Path)
    }
    $processId = if ($text -match '(?m)^ProcessId:\s*(\d+)') { $Matches[1] } else { "unknown" }

    return [pscustomobject]@{ Text = $text; StartedUtc = $startedUtc; ProcessId = $processId }
}

function Enter-M365ScanLock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [datetime]$StartedUtc
    )

    # One scan per output folder. The lock file is created only when it does not exist yet, holds this scan's
    # process id and UTC start time, and stays open until Exit-M365ScanLock. A lock that started more than six
    # hours ago is taken to be left by a scan that was killed, and is taken over with a warning in errors.log.
    $lockPath = Join-Path $OutputPath ".scan.lock"
    $staleAfter = [timespan]::FromHours(6)
    $createError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $stream = $null
        try {
            $stream = [System.IO.FileStream]::new($lockPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        }
        catch {
            $createError = $_
        }

        if ($null -ne $stream) {
            $text = "ProcessId: $PID`nStartedAt: $($StartedUtc.ToString('o', [cultureinfo]::InvariantCulture))`n"
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush()
            }
            catch {
                $stream.Dispose()
                $null = Remove-M365File -Path $lockPath
                throw "Could not write the scan lock $lockPath. $($_.Exception.GetBaseException().Message)"
            }
            return [pscustomobject]@{ Path = $lockPath; Stream = $stream; Text = $text }
        }

        $holder = Read-M365ScanLock -Path $lockPath
        if ($null -eq $holder) {
            # The other scan has just finished, or the lock cannot be created at all. Try again, then say why.
            continue
        }

        $startedText = $holder.StartedUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", [cultureinfo]::InvariantCulture)
        if (([datetime]::UtcNow - $holder.StartedUtc) -lt $staleAfter) {
            throw "Another scan is running in $OutputPath (started $startedText). If no scan is running, delete $lockPath and run the scan again."
        }

        # Read it again just before removing it, so a lock another scan took over a moment ago is left alone.
        $again = Read-M365ScanLock -Path $lockPath
        if ($null -eq $again -or $again.Text -ne $holder.Text) {
            continue
        }
        try {
            [System.IO.File]::Delete($lockPath)
        }
        catch {
            # On Windows a lock that a live scan still holds open cannot be deleted.
            throw "Another scan is running in $OutputPath (started $startedText). Its lock is more than six hours old but is still held open."
        }
        Write-M365MonitorError -Message "Took over the scan lock in $OutputPath from a scan that started $startedText (process $($holder.ProcessId)), more than six hours ago. That scan is taken to have stopped without removing its lock." -OutputPath $OutputPath
    }

    $reason = if ($createError) { $createError.Exception.GetBaseException().Message } else { "Another scan kept taking it." }
    throw "Could not create the scan lock $lockPath. $reason"
}

function Exit-M365ScanLock {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Lock
    )

    # Closes and deletes this scan's lock. It is deleted only while it still holds what this scan wrote, so a lock
    # another scan took over is left alone.
    if ($null -eq $Lock) {
        return
    }

    $Lock.Stream.Dispose()
    $current = Read-M365ScanLock -Path $Lock.Path
    if ($null -ne $current -and $current.Text -eq $Lock.Text -and -not (Remove-M365File -Path $Lock.Path)) {
        Write-Warning "Could not remove the scan lock $($Lock.Path). Delete it before the next scan, or that scan waits until the lock is six hours old."
    }
}

function Get-M365CarriedFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$MailboxFailedUsers = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$RuleFailedUsers = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$NoMailboxUsers = @()
    )

    # Returns the rows of the previous forwarding-findings.json for users whose reads failed in this run, so a known
    # forward does not drop off the report because of one bad read. A failed mailbox read keeps the user's mailbox
    # forwarding rows and a failed inbox rule read keeps the user's inbox rule rows; what this run did read replaces
    # the rest. Each kept row is marked NotRechecked and keeps the DetectedAt of the scan that found it.
    # An account listed under UsersWithoutMailbox has nothing to forward, so its rows are not kept.
    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $mailboxFailed = [System.Collections.Generic.HashSet[string]]::new([string[]]@($MailboxFailedUsers), $comparer)
    $ruleFailed = [System.Collections.Generic.HashSet[string]]::new([string[]]@($RuleFailedUsers), $comparer)
    $noMailbox = [System.Collections.Generic.HashSet[string]]::new([string[]]@($NoMailboxUsers), $comparer)
    if ($mailboxFailed.Count -eq 0 -and $ruleFailed.Count -eq 0) {
        return
    }

    $path = Join-Path $OutputPath "forwarding-findings.json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return
    }

    try {
        $previous = @(Read-M365JsonFile -Path $path)
    }
    catch {
        Write-M365MonitorError -Message "Could not read the previous forwarding-findings.json, so the last scan's findings could not be kept for the users whose reads failed." -ErrorRecord $_ -OutputPath $OutputPath
        return
    }

    foreach ($row in $previous) {
        if ($row -isnot [System.Management.Automation.PSCustomObject]) {
            continue
        }
        $upn = [string]$row.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn) -or $noMailbox.Contains($upn)) {
            continue
        }
        # Plain assignments: an if expression would send the set down the pipeline and hand back its items.
        $failedUsers = $ruleFailed
        if ([string]$row.ForwardingType -eq "MailboxForwarding") {
            $failedUsers = $mailboxFailed
        }
        if (-not $failedUsers.Contains($upn)) {
            continue
        }

        # ConvertFrom-Json turns the ISO 8601 text into a date. Write it back in the form the collectors use.
        if ($row.DetectedAt -is [datetime]) {
            $row.DetectedAt = $row.DetectedAt.ToString("o", [cultureinfo]::InvariantCulture)
        }
        Add-M365Property -InputObject $row -Name "NotRechecked" -Value $true
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
    # cut short, empty) is left exactly as it is, because writing this run's records over it would replace weeks of
    # baseline with one day. The baselines in that run start from no history.
    # Metadata-only baseline: stores sender, counts, domains, and timestamps only.
    # It does not store email subjects, bodies, previews, attachments, or message content.
    $historyPath = Join-Path $OutputPath "outbound-baseline-history.json"
    $history = @()
    $historyUnreadable = $false
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $history = @(Read-M365JsonFile -Path $historyPath)
            foreach ($record in $history) {
                if ($record -isnot [System.Management.Automation.PSCustomObject]) {
                    throw "It holds a value that is not a history record."
                }
                # Every record the tool writes has a DetectedAt. One that is missing or is not a date means the
                # file is not what this tool wrote.
                $null = [datetime]$record.DetectedAt
            }
        }
        catch {
            Write-M365MonitorError -Message "Could not read outbound baseline history $historyPath, so it was left as it is and this run did not add to it. Baselines in this run start from no history. Repair or move the file so the next run can write it." -ErrorRecord $_ -OutputPath $OutputPath
            $history = @()
            $historyUnreadable = $true
        }
    }

    $multiplier = if ($Settings.PSObject.Properties.Name -contains "BaselineMultiplier") { [double]$Settings.BaselineMultiplier } else { 2.5 }
    $minimumSamples = if ($Settings.PSObject.Properties.Name -contains "BaselineMinimumSamples") { [int]$Settings.BaselineMinimumSamples } else { 3 }
    $retentionDays = if ($Settings.PSObject.Properties.Name -contains "BaselineRetentionDays") { [int]$Settings.BaselineRetentionDays } else { 90 }
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
    Write-Host "Scanning mailbox-level forwarding..."
    $failedMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $noMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $mailboxForwarding = @(Get-M365ForwardingInventory -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedMailboxUsers -NoMailboxUsers $noMailboxUsers)
    if ($failedMailboxUsers.Count -gt 0 -and ($failedMailboxUsers.Count + $noMailboxUsers.Count) -ge $scannableUserCount) {
        throw "Mailbox forwarding could not be read for any scanned user ($($failedMailboxUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }

    Write-Host "Scanning inbox forwarding rules..."
    $failedRuleUsers = [System.Collections.Generic.List[string]]::new()
    $noRuleMailboxUsers = [System.Collections.Generic.List[string]]::new()
    $ruleForwarding = @(Get-M365MessageRuleForwarding -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedRuleUsers -NoMailboxUsers $noRuleMailboxUsers)
    if ($failedRuleUsers.Count -gt 0 -and ($failedRuleUsers.Count + $noRuleMailboxUsers.Count) -ge $scannableUserCount) {
        throw "Inbox rules could not be read for any scanned user ($($failedRuleUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }

    # Every finding read in this run was checked in this run. For a user whose reads failed, the last scan's
    # findings are kept and marked, so a known forward does not drop off the report because of one bad read.
    foreach ($finding in @($mailboxForwarding + $ruleForwarding)) {
        Add-M365Property -InputObject $finding -Name "NotRechecked" -Value $false
    }
    $usersWithoutMailbox = @($noMailboxUsers + $noRuleMailboxUsers | Select-Object -Unique)
    $carriedFindings = @(Get-M365CarriedFinding -OutputPath $outputPath -MailboxFailedUsers $failedMailboxUsers -RuleFailedUsers $failedRuleUsers -NoMailboxUsers $usersWithoutMailbox)
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
        "DeliverToMailboxAndForward", "RuleName", "RuleId", "RuleEnabled", "NotRechecked"
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
        $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $TempPath -Encoding UTF8
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "forwarding-findings.csv") -Write {
        param($TempPath)
        $allForwarding |
            ForEach-Object {
                $csvRow = $_.PSObject.Copy()
                foreach ($property in $csvRow.PSObject.Properties) {
                    if ($property.Value -is [string]) { $property.Value = ConvertTo-M365CsvSafeValue $property.Value }
                }
                $csvRow
            } |
            Select-Object -Property $findingColumns |
            Export-Csv -LiteralPath $TempPath -NoTypeInformation
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "outbound-metadata-counts.csv") -Write {
        param($TempPath)
        $outboundCounts |
            Select-Object Date,
                @{ Name = "UserPrincipalName"; Expression = { ConvertTo-M365CsvSafeValue $_.UserPrincipalName } },
                @{ Name = "SenderAddress"; Expression = { ConvertTo-M365CsvSafeValue $_.SenderAddress } },
                ExternalSentCount, UniqueExternalRecipientCount,
                @{ Name = "TopExternalDomains"; Expression = { ConvertTo-M365CsvSafeValue $_.TopExternalDomains } },
                AfterHoursCount, BaselineAverage, BaselineSampleCount, BaselineMultiplier, IsAboveBaseline, CountDeltaFromBaseline, RiskLevel, DetectedAt |
            Export-Csv -LiteralPath $TempPath -NoTypeInformation
    }
    Add-M365StagedFile -Staged $stagedFiles -RunId $runId -Path (Join-Path $outputPath "summary.csv") -Write {
        param($TempPath)
        # One flat row: the failure lists stay in summary.json, the CSV carries their counts.
        $summary |
            Select-Object -Property * -ExcludeProperty CollectionFailures, UsersWithoutMailbox |
            Select-Object -Property *,
                @{ Name = "UsersWithoutMailbox"; Expression = { $summary.UsersWithoutMailbox.Count } },
                @{ Name = "MailboxForwardingFailures"; Expression = { $summary.CollectionFailures.MailboxForwarding.Count } },
                @{ Name = "InboxRuleFailures"; Expression = { $summary.CollectionFailures.InboxRules.Count } } |
            Export-Csv -LiteralPath $TempPath -NoTypeInformation
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
    $dashboard = Join-Path $outputPath "dashboard.html"

    Write-Host ""
    Write-Host "M365 Forwarding Monitor complete. Metadata-only privacy mode is enabled."
    Write-Host "Users scanned: $($summary.TotalUsersScanned)"
    Write-Host "Mailbox forwarding users: $($summary.UsersWithMailboxForwarding)"
    Write-Host "Inbox-rule forwarding users: $($summary.UsersWithInboxRuleForwarding)"
    Write-Host "External forwarding findings: $($summary.ExternalForwardingCount)"
    Write-Host "High/Critical forwarding risks: $($summary.HighCriticalRiskCount)"
    Write-Host "Abnormal outbound metadata rows: $($summary.AbnormalOutboundCount)"
    if ($failedMailboxUsers.Count -gt 0 -or $failedRuleUsers.Count -gt 0 -or $traceStatus.Truncated) {
        Write-Host "INCOMPLETE SCAN: mailbox read failures $($failedMailboxUsers.Count), inbox rule read failures $($failedRuleUsers.Count), message trace truncated $($traceStatus.Truncated). See the dashboard and errors.log."
    }
    Write-Host "Dashboard: $dashboard"
    $isPartialScan = $failedMailboxUsers.Count -gt 0 -or $failedRuleUsers.Count -gt 0
}
catch {
    Write-M365MonitorError -Message "Invoke-ForwardingMonitor failed." -ErrorRecord $_ -OutputPath $outputPath
    throw
}
finally {
    # Deletes this run's temporary files that were not put in place, then lets the next scan in.
    Clear-M365StagedFile -Staged $stagedFiles
    Exit-M365ScanLock -Lock $scanLock
}

# 0 clean run, 1 stopped run (the catch above rethrows), 2 partial scan: the reports are written but some users were not read.
if ($isPartialScan) { exit 2 }
