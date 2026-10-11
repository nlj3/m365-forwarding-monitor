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
    return (Resolve-Path -Path (Join-Path $scriptRoot $Path)).Path
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

function Add-M365StagedFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Staged,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [scriptblock]$Write
    )

    # Writes the new content to a temporary file next to the final path and remembers the pair.
    # Nothing at the final path changes until Publish-M365StagedFile runs.
    $leaf = Split-Path -Leaf $Path
    $tempPath = Join-Path (Split-Path -Parent $Path) (".{0}.{1}.tmp" -f $leaf, [guid]::NewGuid().ToString("N"))
    $Staged.Add([pscustomobject]@{ Path = $Path; TempPath = $tempPath })
    & $Write $tempPath
}

function Publish-M365StagedFile {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Staged
    )

    # Checks every destination first, so a file that cannot be replaced stops the run before any file changes.
    # Then moves the temporary files into place in the order they were staged (the dashboard is staged last).
    foreach ($item in $Staged) {
        if ((Test-Path -LiteralPath $item.Path -PathType Leaf) -and (Get-Item -LiteralPath $item.Path -Force).IsReadOnly) {
            throw "Cannot replace the read-only output file $($item.Path). No output files were changed."
        }
    }

    foreach ($item in $Staged) {
        Move-Item -LiteralPath $item.TempPath -Destination $item.Path -Force
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

    # Returns the history records to write. The caller stages them with the other output files.
    # Metadata-only baseline: stores sender, counts, domains, and timestamps only.
    # It does not store email subjects, bodies, previews, attachments, or message content.
    $historyPath = Join-Path $OutputPath "outbound-baseline-history.json"
    $history = @()
    if (Test-Path -LiteralPath $historyPath) {
        try {
            $history = @(Get-Content -Path $historyPath -Raw | ConvertFrom-Json)
        }
        catch {
            Write-M365MonitorError -Message "Could not read outbound baseline history. Starting fresh." -ErrorRecord $_ -OutputPath $OutputPath
            $history = @()
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
    return , @($retainedHistory + $currentRecords)
}

$settingsFile = Resolve-M365MonitorPath -Path $SettingsPath
$settings = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
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
    $approvedExceptions = @(Import-Csv -Path $exceptionPathCandidate)
}

# Every file the run writes is staged first, then moved into place together, with the dashboard last.
# If anything fails before the move, the files from the previous run are left as they were.
$stagedFiles = [System.Collections.Generic.List[object]]::new()

try {
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
    $mailboxForwarding = @(Get-M365ForwardingInventory -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedMailboxUsers)
    if ($scannableUserCount -gt 0 -and $failedMailboxUsers.Count -ge $scannableUserCount) {
        throw "Mailbox forwarding could not be read for any scanned user ($($failedMailboxUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }

    Write-Host "Scanning inbox forwarding rules..."
    $failedRuleUsers = [System.Collections.Generic.List[string]]::new()
    $ruleForwarding = @(Get-M365MessageRuleForwarding -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath -FailedUsers $failedRuleUsers)
    if ($scannableUserCount -gt 0 -and $failedRuleUsers.Count -ge $scannableUserCount) {
        throw "Inbox rules could not be read for any scanned user ($($failedRuleUsers.Count) of $scannableUserCount failed). No output files were changed. See errors.log."
    }

    Write-Host "Collecting outbound metadata counts..."
    $traceStatus = @{ RowCount = 0; Truncated = $false }
    $outboundCounts = @(Get-M365OutboundMetadataCounts -Settings $settings -OutputPath $outputPath -TraceStatus $traceStatus)
    Write-Host "Updating outbound metadata baseline..."
    $baselineHistory = Update-M365OutboundBaseline -OutboundCounts $outboundCounts -Settings $settings -OutputPath $outputPath
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
        "DeliverToMailboxAndForward", "RuleName", "RuleId", "RuleEnabled"
    )

    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "forwarding-findings.json") -Write {
        param($TempPath)
        Write-M365JsonReport -InputObject $allForwarding -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "outbound-metadata-counts.json") -Write {
        param($TempPath)
        Write-M365JsonReport -InputObject $outboundCounts -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "summary.json") -Write {
        param($TempPath)
        $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $TempPath -Encoding UTF8
    }
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "forwarding-findings.csv") -Write {
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
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "outbound-metadata-counts.csv") -Write {
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
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "summary.csv") -Write {
        param($TempPath)
        # One flat row: the failure lists stay in summary.json, the CSV carries their counts.
        $summary |
            Select-Object -Property * -ExcludeProperty CollectionFailures |
            Select-Object -Property *,
                @{ Name = "MailboxForwardingFailures"; Expression = { $summary.CollectionFailures.MailboxForwarding.Count } },
                @{ Name = "InboxRuleFailures"; Expression = { $summary.CollectionFailures.InboxRules.Count } } |
            Export-Csv -LiteralPath $TempPath -NoTypeInformation
    }
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "outbound-baseline-history.json") -Write {
        param($TempPath)
        Write-M365JsonReport -InputObject $baselineHistory -Path $TempPath
    }
    Add-M365StagedFile -Staged $stagedFiles -Path (Join-Path $outputPath "dashboard.html") -Write {
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
}
catch {
    Clear-M365StagedFile -Staged $stagedFiles
    Write-M365MonitorError -Message "Invoke-ForwardingMonitor failed." -ErrorRecord $_ -OutputPath $outputPath
    throw
}
