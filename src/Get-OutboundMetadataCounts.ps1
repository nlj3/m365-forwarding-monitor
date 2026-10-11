# M365 Forwarding Monitor is metadata-only. This script counts outbound message
# trace metadata only. It does not store subject, body, previews, attachments, or content.

function Get-M365OutboundMetadataCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter()]
        [string]$OutputPath = "./output",

        # Receives RowCount and Truncated. Truncated is true when the trace returned as many rows as it was allowed to.
        [Parameter()]
        [hashtable]$TraceStatus = @{}
    )

    # Message trace times are UTC. After-hours counting uses the hour in the business time zone.
    # This throws on an unknown time zone before any call is made.
    $timeZone = Get-M365BusinessHoursTimeZone -Settings $Settings
    $resultSize = 5000

    $detectedAt = (Get-Date).ToString("o")
    $endDate = Get-Date
    $startDate = $endDate.AddHours(-1 * [int]$Settings.LookbackHours)
    $internalDomains = @($Settings.InternalDomains | ForEach-Object { $_.ToLowerInvariant() })
    $results = [System.Collections.Generic.List[object]]::new()

    # One call returns the whole trace. If it fails, the scan has no outbound data, so it throws and the run stops.
    $traces = Invoke-M365CallWithRetry -OperationName "Get-MessageTraceV2 outbound metadata" -OutputPath $OutputPath -ThrowOnFailure -ScriptBlock {
        Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $resultSize -ErrorAction Stop |
            Select-Object Received, SenderAddress, RecipientAddress, Directionality, Status
    }

    $rowCount = if ($null -eq $traces) { 0 } else { @($traces).Count }
    $TraceStatus["RowCount"] = $rowCount
    $TraceStatus["Truncated"] = $rowCount -ge $resultSize
    if ($TraceStatus["Truncated"]) {
        Write-M365MonitorError -Message "Message trace returned the maximum of $resultSize rows, so outbound counts may be too low." -OutputPath $OutputPath
    }

    if ($null -eq $traces) {
        return @()
    }

    $externalOutbound = @($traces | Where-Object {
        $senderAddress = [string]$_.SenderAddress
        $recipient = [string]$_.RecipientAddress
        $recipientDomain = Get-M365TargetDomain -Target $recipient
        $senderAddress -like "*@*" -and
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
            $hour = Get-M365BusinessHour -Received ([datetime]$_.Received) -TimeZone $timeZone
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
