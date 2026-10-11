# M365 Forwarding Monitor dashboard displays metadata-only risk indicators.
# It never displays email subjects, bodies, previews, attachment contents, or message content.

function ConvertTo-M365Html {
    param([Parameter()][string]$Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-M365ForwardingDashboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Summary,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ForwardingFindings,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$OutboundCounts,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $dashboardPath = Join-Path $OutputPath "dashboard.html"
    $generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")

    $riskOrder = @{ Critical = 1; High = 2; Medium = 3; Low = 4; Exception = 5; Approved = 5 }
    $topRisky = @($ForwardingFindings |
        Where-Object { $_.RiskLevel -in @("Critical", "High") } |
        Sort-Object @{ Expression = { $riskOrder[$_.RiskLevel] } }, UserPrincipalName |
        Select-Object -First 25)

    $topDomains = @($ForwardingFindings |
        Where-Object { $_.IsExternal -and $_.TargetDomain } |
        Group-Object TargetDomain |
        Sort-Object Count -Descending |
        Select-Object -First 10)

    $abnormalOutbound = @($OutboundCounts |
        Where-Object { $_.RiskLevel -in @("Critical", "Medium") } |
        Sort-Object @{ Expression = { $riskOrder[$_.RiskLevel] } }, ExternalSentCount -Descending)

    $cardHtml = @(
        @{ Label = "Total users scanned"; Value = $Summary.TotalUsersScanned },
        @{ Label = "Mailbox forwarding"; Value = $Summary.UsersWithMailboxForwarding },
        @{ Label = "Inbox-rule forwarding"; Value = $Summary.UsersWithInboxRuleForwarding },
        @{ Label = "External forwarding"; Value = $Summary.ExternalForwardingCount },
        @{ Label = "Personal-domain forwarding"; Value = $Summary.PersonalDomainForwardingCount },
        @{ Label = "Configured exceptions"; Value = $Summary.ApprovedExceptionsCount },
        @{ Label = "High/Critical risks"; Value = $Summary.HighCriticalRiskCount },
        @{ Label = "Abnormal outbound senders"; Value = $Summary.AbnormalOutboundCount },
        @{ Label = "Above personal average"; Value = $Summary.AboveBaselineOutboundCount }
    ) | ForEach-Object {
        "<section class='card'><span>$($_.Label)</span><strong>$($_.Value)</strong></section>"
    }

    $riskRows = if ($topRisky.Count -gt 0) {
        $topRisky | ForEach-Object {
            "<tr><td>$(ConvertTo-M365Html $_.UserPrincipalName)</td><td>$(ConvertTo-M365Html $_.ForwardingType)</td><td>$(ConvertTo-M365Html $_.ForwardTarget)</td><td>$(ConvertTo-M365Html $_.TargetDomain)</td><td><span class='badge $($_.RiskLevel)'>$($_.RiskLevel)</span></td><td>$(ConvertTo-M365Html $_.DetectedAt)</td></tr>"
        }
    }
    else {
        "<tr><td colspan='6' class='empty'>No high or critical forwarding risks found.</td></tr>"
    }

    $domainRows = if ($topDomains.Count -gt 0) {
        $topDomains | ForEach-Object {
            "<tr><td>$(ConvertTo-M365Html $_.Name)</td><td>$($_.Count)</td></tr>"
        }
    }
    else {
        "<tr><td colspan='2' class='empty'>No external forwarding domains found.</td></tr>"
    }

    $outboundRows = if ($abnormalOutbound.Count -gt 0) {
        $abnormalOutbound | ForEach-Object {
            $domains = if ($_.TopExternalDomains) { $_.TopExternalDomains -join "; " } else { "" }
            $baseline = if ($null -ne $_.BaselineAverage) { $_.BaselineAverage } else { "Learning" }
            $delta = if ($null -ne $_.CountDeltaFromBaseline) { $_.CountDeltaFromBaseline } else { "" }
            "<tr><td>$(ConvertTo-M365Html $_.SenderAddress)</td><td>$($_.ExternalSentCount)</td><td>$($_.UniqueExternalRecipientCount)</td><td>$(ConvertTo-M365Html $baseline)</td><td>$(ConvertTo-M365Html $delta)</td><td>$($_.BaselineSampleCount)</td><td>$($_.IsAboveBaseline)</td><td>$(ConvertTo-M365Html $domains)</td><td>$($_.AfterHoursCount)</td><td><span class='badge $($_.RiskLevel)'>$($_.RiskLevel)</span></td></tr>"
        }
    }
    else {
        "<tr><td colspan='10' class='empty'>No abnormal outbound metadata counts found.</td></tr>"
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M365 Forwarding Monitor</title>
  <style>
    :root { color-scheme: light; --bg:#f6f7f9; --panel:#ffffff; --ink:#1f2933; --muted:#667085; --line:#d7dde5; --critical:#b42318; --high:#b54708; --medium:#a15c07; --low:#2f6b45; --exception:#2559a7; }
    body { margin:0; font-family: "Segoe UI", Arial, sans-serif; background:var(--bg); color:var(--ink); }
    header { padding:28px 36px 16px; background:#ffffff; border-bottom:1px solid var(--line); }
    h1 { margin:0 0 8px; font-size:28px; font-weight:650; letter-spacing:0; }
    header p { margin:0; color:var(--muted); max-width:920px; line-height:1.45; }
    main { padding:24px 36px 40px; }
    .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:14px; margin-bottom:22px; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; min-height:82px; box-sizing:border-box; }
    .card span { display:block; color:var(--muted); font-size:13px; margin-bottom:10px; }
    .card strong { display:block; font-size:30px; line-height:1; }
    section.table-panel { margin-top:18px; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    h2 { font-size:17px; margin:0; padding:16px 18px; border-bottom:1px solid var(--line); }
    table { width:100%; border-collapse:collapse; font-size:14px; }
    th, td { padding:11px 14px; border-bottom:1px solid #edf0f4; text-align:left; vertical-align:top; }
    th { color:#344054; background:#fbfcfd; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    tr:last-child td { border-bottom:none; }
    .badge { display:inline-block; min-width:68px; text-align:center; padding:4px 8px; border-radius:999px; color:#fff; font-size:12px; font-weight:650; }
    .Critical { background:var(--critical); } .High { background:var(--high); } .Medium { background:var(--medium); } .Low { background:var(--low); } .Exception, .Approved { background:var(--exception); }
    .empty { color:var(--muted); text-align:center; padding:22px; }
    footer { color:var(--muted); font-size:12px; padding:0 36px 26px; }
    @media (max-width: 720px) { header, main, footer { padding-left:18px; padding-right:18px; } table { display:block; overflow-x:auto; white-space:nowrap; } }
  </style>
</head>
<body>
  <header>
    <h1>Microsoft 365 Forwarding Monitor</h1>
    <p>Generated $generatedAt. Metadata-only dashboard: no email bodies, subjects, message previews, attachment contents, or individual message content are collected or displayed.</p>
  </header>
  <main>
    <div class="cards">
      $($cardHtml -join "`n      ")
    </div>
    <section class="table-panel">
      <h2>Top Risky Users</h2>
      <table>
        <thead><tr><th>User</th><th>Type</th><th>Target</th><th>Domain</th><th>Risk</th><th>Detected</th></tr></thead>
        <tbody>$($riskRows -join "`n")</tbody>
      </table>
    </section>
    <section class="table-panel">
      <h2>Top External Domains</h2>
      <table>
        <thead><tr><th>Domain</th><th>Forwarding Findings</th></tr></thead>
        <tbody>$($domainRows -join "`n")</tbody>
      </table>
    </section>
    <section class="table-panel">
      <h2>Abnormal Outbound Metadata Counts</h2>
      <table>
        <thead><tr><th>Sender</th><th>External Sent</th><th>Unique Recipients</th><th>Personal Avg</th><th>Delta</th><th>Samples</th><th>Above Avg</th><th>Top Domains</th><th>After Hours</th><th>Risk</th></tr></thead>
        <tbody>$($outboundRows -join "`n")</tbody>
      </table>
    </section>
  </main>
  <footer>Detection only. Review findings before taking administrative action.</footer>
</body>
</html>
"@

    Set-Content -Path $dashboardPath -Value $html -Encoding UTF8
    return $dashboardPath
}
