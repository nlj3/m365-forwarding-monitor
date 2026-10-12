# M365 Forwarding Monitor is metadata-only. This script checks mailbox forwarding
# configuration only and never reads email bodies, subjects, previews, or attachments.

function Get-M365ForwardingInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Users,

        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter()]
        [object[]]$ApprovedExceptions = @(),

        [Parameter()]
        [string]$OutputPath = "./output",

        # Receives the user principal name of every user whose mailbox could not be read.
        [Parameter()]
        [System.Collections.Generic.List[string]]$FailedUsers = [System.Collections.Generic.List[string]]::new(),

        # Receives the user principal name of every user who has no mailbox. That is not a failure.
        [Parameter()]
        [System.Collections.Generic.List[string]]$NoMailboxUsers = [System.Collections.Generic.List[string]]::new()
    )

    $detectedAt = (Get-Date).ToString("o")
    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($user in $Users) {
        $upn = [string]$user.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn)) {
            continue
        }

        # A mailbox that cannot be read is counted, never skipped silently: a scan that cannot see must not look clean.
        try {
            $mailbox = Invoke-M365CallWithRetry -OperationName "Get-Mailbox $upn" -OutputPath $OutputPath -ThrowOnFailure -NoRetryPattern (Get-M365NoMailboxPattern -Source Mailbox) -ScriptBlock {
                Get-Mailbox -Identity $upn -ErrorAction Stop |
                    Select-Object DisplayName, UserPrincipalName, PrimarySmtpAddress, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
            }
        }
        catch {
            if (Test-M365NoMailboxError -ErrorRecord $_ -Source Mailbox) {
                $NoMailboxUsers.Add($upn)
            }
            else {
                $FailedUsers.Add($upn)
            }
            continue
        }

        if ($null -eq $mailbox) {
            $FailedUsers.Add($upn)
            continue
        }

        $targets = @()
        if ($mailbox.ForwardingSmtpAddress) { $targets += [string]$mailbox.ForwardingSmtpAddress }
        if ($mailbox.ForwardingAddress) { $targets += [string]$mailbox.ForwardingAddress }

        foreach ($target in ($targets | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
            $domain = Get-M365TargetDomain -Target $target
            $isExternal = -not (Test-M365InternalDomain -Domain $domain -InternalDomains $Settings.InternalDomains)
            $isPersonal = Test-M365PersonalDomain -Domain $domain -PersonalDomains $Settings.PersonalDomains
            $approved = Test-M365ApprovedException -UserPrincipalName $upn -Target $target -ApprovedExceptions $ApprovedExceptions
            $risk = Get-M365ForwardingRiskLevel -RuleEnabled $true -IsExternal $isExternal -IsPersonalDomain $isPersonal -ApprovedException $approved

            $results.Add([pscustomobject]@{
                UserPrincipalName          = $upn
                DisplayName                = $mailbox.DisplayName
                ForwardingType             = "MailboxForwarding"
                ForwardTarget              = $target
                TargetDomain               = $domain
                IsExternal                 = [bool]$isExternal
                IsPersonalDomain           = [bool]$isPersonal
                DeliverToMailboxAndForward = [bool]$mailbox.DeliverToMailboxAndForward
                ApprovedException          = [bool]$approved
                RiskLevel                  = $risk
                DetectedAt                 = $detectedAt
            })
        }
    }

    return @($results)
}
