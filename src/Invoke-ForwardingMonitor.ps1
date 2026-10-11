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

function Update-M365OutboundBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$OutboundCounts,

        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

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
    @($retainedHistory + $currentRecords) |
        ConvertTo-Json -Depth 8 |
        Set-Content -Path $historyPath -Encoding UTF8
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

try {
    if (-not $SkipConnect) {
        Connect-M365Monitor -Settings $settings -OutputPath $outputPath -UseDeviceAuthentication:$UseDeviceAuthentication
    }

    Write-Host "Collecting user list..."
    $users = @(Get-M365MonitorUsers -OutputPath $outputPath)
    if ($users.Count -eq 0) {
        throw "No users were returned from Microsoft Graph. Check Graph authentication and permissions: User.Read.All and MailboxSettings.Read."
    }

    Write-Host "Scanning mailbox-level forwarding..."
    $mailboxForwarding = @(Get-M365ForwardingInventory -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath)
    Write-Host "Scanning inbox forwarding rules..."
    $ruleForwarding = @(Get-M365MessageRuleForwarding -Users $users -Settings $settings -ApprovedExceptions $approvedExceptions -OutputPath $outputPath)
    Write-Host "Collecting outbound metadata counts..."
    $outboundCounts = @(Get-M365OutboundMetadataCounts -Settings $settings -OutputPath $outputPath)
    Write-Host "Updating outbound metadata baseline..."
    Update-M365OutboundBaseline -OutboundCounts $outboundCounts -Settings $settings -OutputPath $outputPath
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
    }

    $allForwarding | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $outputPath "forwarding-findings.json") -Encoding UTF8
    $outboundCounts | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $outputPath "outbound-metadata-counts.json") -Encoding UTF8
    $summary | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $outputPath "summary.json") -Encoding UTF8

    $allForwarding | Export-Csv -Path (Join-Path $outputPath "forwarding-findings.csv") -NoTypeInformation
    $outboundCounts |
        Select-Object Date, UserPrincipalName, SenderAddress, ExternalSentCount, UniqueExternalRecipientCount,
            @{ Name = "TopExternalDomains"; Expression = { ConvertTo-M365CsvSafeValue $_.TopExternalDomains } },
            AfterHoursCount, BaselineAverage, BaselineSampleCount, BaselineMultiplier, IsAboveBaseline, CountDeltaFromBaseline, RiskLevel, DetectedAt |
        Export-Csv -Path (Join-Path $outputPath "outbound-metadata-counts.csv") -NoTypeInformation
    $summary | Export-Csv -Path (Join-Path $outputPath "summary.csv") -NoTypeInformation

    $dashboard = New-M365ForwardingDashboard -Summary $summary -ForwardingFindings $allForwarding -OutboundCounts $outboundCounts -OutputPath $outputPath

    Write-Host ""
    Write-Host "M365 Forwarding Monitor complete. Metadata-only privacy mode is enabled."
    Write-Host "Users scanned: $($summary.TotalUsersScanned)"
    Write-Host "Mailbox forwarding users: $($summary.UsersWithMailboxForwarding)"
    Write-Host "Inbox-rule forwarding users: $($summary.UsersWithInboxRuleForwarding)"
    Write-Host "External forwarding findings: $($summary.ExternalForwardingCount)"
    Write-Host "High/Critical forwarding risks: $($summary.HighCriticalRiskCount)"
    Write-Host "Abnormal outbound metadata rows: $($summary.AbnormalOutboundCount)"
    Write-Host "Dashboard: $dashboard"
}
catch {
    Write-M365MonitorError -Message "Invoke-ForwardingMonitor failed." -ErrorRecord $_ -OutputPath $outputPath
    throw
}
