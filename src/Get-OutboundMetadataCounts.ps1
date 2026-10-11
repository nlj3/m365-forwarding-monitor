# M365 Forwarding Monitor is metadata-only. This script counts outbound message
# trace metadata only. It does not store subject, body, previews, attachments, or content.

function Get-M365OutboundMetadataCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter()]
        [string]$OutputPath = "./output"
    )

    $detectedAt = (Get-Date).ToString("o")
    $endDate = Get-Date
    $startDate = $endDate.AddHours(-1 * [int]$Settings.LookbackHours)
    $internalDomains = @($Settings.InternalDomains | ForEach-Object { $_.ToLowerInvariant() })
    $results = New-Object System.Collections.Generic.List[object]

    $traces = Invoke-M365CallWithRetry -OperationName "Get-MessageTraceV2 outbound metadata" -OutputPath $OutputPath -ScriptBlock {
        Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ErrorAction Stop |
            Select-Object Received, SenderAddress, RecipientAddress, Directionality, Status
    }

    if ($null -eq $traces) {
        return @()
    }

    $externalOutbound = @($traces | Where-Object {
        $sender = [string]$_.SenderAddress
        $recipient = [string]$_.RecipientAddress
        $recipientDomain = Get-M365TargetDomain -Target $recipient
        $sender -like "*@*" -and
        $recipient -like "*@*" -and
        -not ($internalDomains -contains $recipientDomain)
    })

    $grouped = $externalOutbound | Group-Object -Property SenderAddress
    foreach ($group in $grouped) {
        $items = @($group.Group)
        $recipientDomains = @($items | ForEach-Object { Get-M365TargetDomain -Target ([string]$_.RecipientAddress) } | Where-Object { $_ } )
        $topDomains = @(
            $recipientDomains |
                Group-Object |
                Sort-Object Count -Descending |
                Select-Object -First 5 |
                ForEach-Object { "$($_.Name):$($_.Count)" }
        )

        $afterHours = @($items | Where-Object {
            $hour = ([datetime]$_.Received).Hour
            $hour -lt [int]$Settings.BusinessHoursStart -or $hour -ge [int]$Settings.BusinessHoursEnd
        }).Count

        $count = $items.Count
        $risk = Get-M365OutboundRiskLevel -ExternalSentCount $count -AfterHoursCount $afterHours -Settings $Settings

        $results.Add([pscustomobject]@{
            Date                         = $endDate.ToString("yyyy-MM-dd")
            UserPrincipalName            = $group.Name
            SenderAddress                = $group.Name
            ExternalSentCount            = [int]$count
            UniqueExternalRecipientCount = [int](@($items.RecipientAddress | Select-Object -Unique).Count)
            TopExternalDomains           = $topDomains
            AfterHoursCount              = [int]$afterHours
            BaselineAverage              = $null
            BaselineSampleCount          = 0
            BaselineMultiplier           = [double]$Settings.BaselineMultiplier
            IsAboveBaseline              = $false
            CountDeltaFromBaseline       = $null
            RiskLevel                    = $risk
            DetectedAt                   = $detectedAt
        })
    }

    return @($results)
}
