# M365 Forwarding Monitor is metadata-only. This script reads inbox rule metadata
# and forwarding targets only; it never reads email bodies, subjects, previews, or attachments.

function Get-M365MessageRuleForwarding {
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

        # Receives the user principal name of every user whose inbox rules could not be read.
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

        # Rules that cannot be read are counted, never skipped silently: a scan that cannot see must not look clean.
        try {
            # The user name is encoded for the URL: a guest member's name holds #EXT#, and an unencoded # would end
            # the path there and start a fragment.
            $rules = Invoke-M365CallWithRetry -OperationName "Graph messageRules $upn" -OutputPath $OutputPath -ThrowOnFailure -NoRetryWhen { param($ErrorRecord) Test-M365NoMailboxError -ErrorRecord $ErrorRecord -Source InboxRules } -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$([System.Uri]::EscapeDataString($upn))/mailFolders/inbox/messageRules" -ErrorAction Stop
            }
        }
        catch {
            if (Test-M365NoMailboxError -ErrorRecord $_ -Source InboxRules) {
                $NoMailboxUsers.Add($upn)
            }
            else {
                $FailedUsers.Add($upn)
            }
            continue
        }

        if ($null -eq $rules) {
            $FailedUsers.Add($upn)
            continue
        }

        if ($null -eq $rules.value) {
            continue
        }

        foreach ($rule in @($rules.value)) {
            $actions = $rule.actions
            if ($null -eq $actions) {
                continue
            }

            $actionMap = @(
                @{ Property = "forwardTo"; Type = "InboxRuleForward" },
                @{ Property = "redirectTo"; Type = "InboxRuleRedirect" },
                @{ Property = "forwardAsAttachmentTo"; Type = "InboxRuleForwardAsAttachment" }
            )

            foreach ($action in $actionMap) {
                $recipients = @($actions.($action.Property))
                if (-not $recipients -or $recipients.Count -eq 0) {
                    continue
                }

                foreach ($recipient in $recipients) {
                    $target = $null
                    if ($recipient.emailAddress.address) {
                        $target = [string]$recipient.emailAddress.address
                    }
                    elseif ($recipient.address) {
                        $target = [string]$recipient.address
                    }
                    elseif ($recipient.emailAddress.name) {
                        $target = [string]$recipient.emailAddress.name
                    }

                    if ([string]::IsNullOrWhiteSpace($target)) {
                        continue
                    }

                    $domain = Get-M365TargetDomain -Target $target
                    $isExternal = -not (Test-M365InternalDomain -Domain $domain -InternalDomains $Settings.InternalDomains)
                    $isPersonal = Test-M365PersonalDomain -Domain $domain -PersonalDomains $Settings.PersonalDomains
                    $approved = Test-M365ApprovedException -UserPrincipalName $upn -Target $target -ApprovedExceptions $ApprovedExceptions
                    $enabled = if ($null -eq $rule.isEnabled) { $true } else { [bool]$rule.isEnabled }
                    $risk = Get-M365ForwardingRiskLevel -RuleEnabled $enabled -IsExternal $isExternal -IsPersonalDomain $isPersonal -ApprovedException $approved

                    $results.Add([pscustomobject]@{
                        UserPrincipalName = $upn
                        DisplayName       = $user.DisplayName
                        ForwardingType    = $action.Type
                        RuleName          = $rule.displayName
                        RuleId            = $rule.id
                        RuleEnabled       = $enabled
                        ForwardTarget     = $target
                        TargetDomain      = $domain
                        IsExternal        = [bool]$isExternal
                        IsPersonalDomain  = [bool]$isPersonal
                        ApprovedException = [bool]$approved
                        RiskLevel         = $risk
                        DetectedAt        = $detectedAt
                    })
                }
            }
        }
    }

    return @($results)
}
