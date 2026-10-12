<#
.SYNOPSIS
Renders the forwarding dashboard from made-up data, with no tenant and no network access.

.DESCRIPTION
Builds a small synthetic result set in the same shape the collectors in src/ produce, then
passes it to New-M365ForwardingDashboard from src/New-Dashboard.ps1 and writes dashboard.html.

The scoring fields (TargetDomain, IsExternal, IsPersonalDomain, ApprovedException, RiskLevel)
are computed with the real functions in src/RiskScoring.psm1, so the sample shows what the
tool would label these cases. The thresholds and internal domains come from
config/settings.example.json.

The data is invented. Users are at contoso.com and every external address is at example.com.
The set has eight users: one approved exception, two external forwards, one forward to a
personal domain, one outbound-volume anomaly, and the rest with nothing to report.

Nothing is read from or written to Microsoft 365. The only file written is dashboard.html.

.PARAMETER OutputPath
Folder that receives dashboard.html. Defaults to the folder this script is in.

.EXAMPLE
pwsh -NoProfile -File ./samples/New-SampleDashboard.ps1

Writes samples/dashboard.html when run from the repository root.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

Import-Module (Join-Path $repoRoot 'src/RiskScoring.psm1') -Force
. (Join-Path $repoRoot 'src/New-Dashboard.ps1')

$settings = Get-Content -Path (Join-Path $repoRoot 'config/settings.example.json') -Raw | ConvertFrom-Json
# Add a personal-mail domain under example.com so the sample does not name a real mail provider.
$settings.PersonalDomains = @($settings.PersonalDomains) + 'personal-mail.example.com'

$detectedAt = (Get-Date).ToString('o')

# No expiry date on the sample exception, so the date check is not involved.
$approvedExceptions = @(
    [pscustomobject]@{
        UserPrincipalName = 'alex.wilber@contoso.com'
        ApprovedTarget    = 'records-archive@partner.example.com'
        Reason            = 'Synthetic sample exception'
        ApprovedBy        = 'security.manager@contoso.com'
        ExpirationDate    = ''
    }
)

function Get-SampleFinding {
    param(
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [Parameter(Mandatory)][string]$ForwardingType,
        [Parameter(Mandatory)][string]$Target,
        [string]$RuleName,
        [bool]$RuleEnabled = $true,
        [bool]$DeliverToMailboxAndForward = $true
    )

    $domain = Get-M365TargetDomain -Target $Target
    $isExternal = -not (Test-M365InternalDomain -Domain $domain -InternalDomains $settings.InternalDomains)
    $isPersonal = Test-M365PersonalDomain -Domain $domain -PersonalDomains $settings.PersonalDomains
    $approved = Test-M365ApprovedException -UserPrincipalName $UserPrincipalName -Target $Target -ApprovedExceptions $approvedExceptions
    $risk = Get-M365ForwardingRiskLevel -RuleEnabled $RuleEnabled -IsExternal $isExternal -IsPersonalDomain $isPersonal -ApprovedException $approved
    $displayName = (($UserPrincipalName -split '@')[0] -split '\.' | ForEach-Object { (Get-Culture).TextInfo.ToTitleCase($_) }) -join ' '

    if ($ForwardingType -eq 'MailboxForwarding') {
        return [pscustomobject]@{
            UserPrincipalName          = $UserPrincipalName
            DisplayName                = $displayName
            ForwardingType             = $ForwardingType
            ForwardTarget              = $Target
            TargetDomain               = $domain
            IsExternal                 = [bool]$isExternal
            IsPersonalDomain           = [bool]$isPersonal
            DeliverToMailboxAndForward = $DeliverToMailboxAndForward
            ApprovedException          = [bool]$approved
            RiskLevel                  = $risk
            DetectedAt                 = $detectedAt
        }
    }

    return [pscustomobject]@{
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $displayName
        ForwardingType    = $ForwardingType
        RuleName          = $RuleName
        RuleId            = '00000000-0000-0000-0000-000000000000'
        RuleEnabled       = $RuleEnabled
        ForwardTarget     = $Target
        TargetDomain      = $domain
        IsExternal        = [bool]$isExternal
        IsPersonalDomain  = [bool]$isPersonal
        ApprovedException = [bool]$approved
        RiskLevel         = $risk
        DetectedAt        = $detectedAt
    }
}

function Get-SampleOutboundRow {
    param(
        [Parameter(Mandatory)][string]$SenderAddress,
        [Parameter(Mandatory)][int]$Sent,
        [Parameter(Mandatory)][int]$UniqueRecipients,
        [Parameter(Mandatory)][string[]]$TopDomains,
        [int]$AfterHours = 0,
        [nullable[double]]$BaselineAverage,
        [int]$Samples = 0
    )

    # Same baseline rule as Update-M365OutboundBaseline in src/Invoke-ForwardingMonitor.ps1.
    $isAbove = $false
    if ($Samples -ge [int]$settings.BaselineMinimumSamples -and $BaselineAverage -gt 0) {
        $isAbove = [double]$Sent -ge ([double]$BaselineAverage * [double]$settings.BaselineMultiplier)
    }
    $delta = if ($null -ne $BaselineAverage) { [Math]::Round([double]$Sent - [double]$BaselineAverage, 2) } else { $null }
    $risk = Get-M365OutboundRiskLevel -ExternalSentCount $Sent -AfterHoursCount $AfterHours -BaselineAverage $BaselineAverage `
        -BaselineSampleCount $Samples -IsAboveBaseline $isAbove -Settings $settings

    return [pscustomobject]@{
        Date                         = (Get-Date).ToString('yyyy-MM-dd')
        UserPrincipalName            = $SenderAddress
        SenderAddress                = $SenderAddress
        ExternalSentCount            = $Sent
        UniqueExternalRecipientCount = $UniqueRecipients
        TopExternalDomains           = $TopDomains
        AfterHoursCount              = $AfterHours
        BaselineAverage              = $BaselineAverage
        BaselineSampleCount          = $Samples
        BaselineMultiplier           = [double]$settings.BaselineMultiplier
        IsAboveBaseline              = $isAbove
        CountDeltaFromBaseline       = $delta
        RiskLevel                    = $risk
        DetectedAt                   = $detectedAt
    }
}

$users = @(
    'alex.wilber', 'jordan.reyes', 'sam.okafor', 'priya.nair',
    'chris.lindqvist', 'taylor.moreau', 'robin.castellan', 'morgan.ellis'
) | ForEach-Object { "$_@contoso.com" }

$mailboxForwarding = @(
    Get-SampleFinding -UserPrincipalName 'alex.wilber@contoso.com' -ForwardingType 'MailboxForwarding' -Target 'records-archive@partner.example.com'
    Get-SampleFinding -UserPrincipalName 'sam.okafor@contoso.com' -ForwardingType 'MailboxForwarding' -Target 'reports@analytics.example.com' -DeliverToMailboxAndForward $false
)

$ruleForwarding = @(
    Get-SampleFinding -UserPrincipalName 'jordan.reyes@contoso.com' -ForwardingType 'InboxRuleForward' -RuleName 'Copy invoices to bookkeeper' -Target 'invoices@vendor.example.com'
    Get-SampleFinding -UserPrincipalName 'priya.nair@contoso.com' -ForwardingType 'InboxRuleRedirect' -RuleName 'Keep a copy at home' -Target 'priya.nair.home@personal-mail.example.com'
)

$outboundCounts = @(
    Get-SampleOutboundRow -SenderAddress 'jordan.reyes@contoso.com' -Sent 14 -UniqueRecipients 9 -TopDomains 'vendor.example.com:9', 'partner.example.com:5' -BaselineAverage 12.8 -Samples 8
    Get-SampleOutboundRow -SenderAddress 'chris.lindqvist@contoso.com' -Sent 31 -UniqueRecipients 18 -TopDomains 'partner.example.com:20', 'vendor.example.com:11' -AfterHours 2 -BaselineAverage 28.4 -Samples 12
    Get-SampleOutboundRow -SenderAddress 'taylor.moreau@contoso.com' -Sent 62 -UniqueRecipients 47 -TopDomains 'analytics.example.com:30', 'partner.example.com:19', 'vendor.example.com:13' -AfterHours 6 -BaselineAverage 22.4 -Samples 6
    Get-SampleOutboundRow -SenderAddress 'robin.castellan@contoso.com' -Sent 8 -UniqueRecipients 6 -TopDomains 'partner.example.com:8' -BaselineAverage 9.1 -Samples 10
    Get-SampleOutboundRow -SenderAddress 'morgan.ellis@contoso.com' -Sent 17 -UniqueRecipients 12 -TopDomains 'vendor.example.com:17' -Samples 1 -BaselineAverage 15
)

$allForwarding = @($mailboxForwarding + $ruleForwarding)

# Same counts as the summary object built in src/Invoke-ForwardingMonitor.ps1.
$summary = [pscustomobject]@{
    GeneratedAt                   = (Get-Date).ToString('o')
    PrivacyMode                   = $true
    TotalUsersScanned             = $users.Count
    UsersWithMailboxForwarding    = @($mailboxForwarding.UserPrincipalName | Select-Object -Unique).Count
    UsersWithInboxRuleForwarding  = @($ruleForwarding.UserPrincipalName | Select-Object -Unique).Count
    ExternalForwardingCount       = @($allForwarding | Where-Object { $_.IsExternal }).Count
    PersonalDomainForwardingCount = @($allForwarding | Where-Object { $_.IsPersonalDomain }).Count
    ApprovedExceptionsCount       = @($allForwarding | Where-Object { $_.ApprovedException }).Count
    HighCriticalRiskCount         = @($allForwarding | Where-Object { $_.RiskLevel -in @('High', 'Critical') }).Count
    AbnormalOutboundCount         = @($outboundCounts | Where-Object { $_.RiskLevel -in @('Medium', 'Critical') }).Count
    AboveBaselineOutboundCount    = @($outboundCounts | Where-Object { $_.IsAboveBaseline }).Count
    TraceTruncated                = $false
    UsersWithoutMailbox           = [pscustomobject]@{ Count = 0; UserPrincipalNames = @() }
    CollectionFailures            = [pscustomobject]@{
        MailboxForwarding = [pscustomobject]@{ Count = 0; UserPrincipalNames = @() }
        InboxRules        = [pscustomobject]@{ Count = 0; UserPrincipalNames = @() }
    }
}

New-M365ForwardingDashboard -Summary $summary -ForwardingFindings $allForwarding -OutboundCounts $outboundCounts -OutputPath $OutputPath
