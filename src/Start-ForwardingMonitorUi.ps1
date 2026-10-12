[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProjectRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)),

    [Parameter()]
    [int]$Port = 8181
)

# M365 Forwarding Monitor local UI.
# Localhost-only, metadata-only control surface. It starts the existing detector and
# serves generated JSON/CSV/HTML metadata reports. It does not read or display email
# bodies, subjects, previews, attachment contents, or individual message content.

$ErrorActionPreference = "Stop"

$resolvedProjectRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$outputPath = Join-Path $resolvedProjectRoot "output"
$dashboardPath = Join-Path $outputPath "dashboard.html"
$summaryPath = Join-Path $outputPath "summary.json"
$errorsPath = Join-Path $outputPath "errors.log"
$scanLogPath = Join-Path $outputPath "scan-latest.log"
$scanStatusPath = Join-Path $outputPath "scan-status.json"

if (-not (Test-Path -LiteralPath $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

$script:ScanJob = $null

function ConvertTo-JsonResponse {
    param([Parameter(Mandatory)][object]$Value)
    return ($Value | ConvertTo-Json -Depth 8)
}

function Send-UiResponse {
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter()]
        [string]$Body = "",

        [Parameter()]
        [string]$ContentType = "text/plain; charset=utf-8",

        [Parameter()]
        [int]$StatusCode = 200
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = $ContentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Send-UiFile {
    param(
        [Parameter(Mandatory)]
        [System.Net.HttpListenerContext]$Context,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [string]$ContentType = "text/html; charset=utf-8"
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Send-UiResponse -Context $Context -StatusCode 404 -ContentType "text/html; charset=utf-8" -Body "<!doctype html><title>Not ready</title><body><h1>Dashboard not ready</h1><p>Run a scan to generate dashboard.html.</p></body>"
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $Context.Response.StatusCode = 200
    $Context.Response.ContentType = $ContentType
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Get-UiFileTail {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [int]$LineCount = 80
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return ""
    }

    return ((Get-Content -LiteralPath $Path -Tail $LineCount -ErrorAction SilentlyContinue) -join "`n")
}

function Get-UiSummary {
    if (-not (Test-Path -LiteralPath $summaryPath)) {
        return $null
    }

    try {
        return (Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-UiAuthChallenge {
    param(
        [Parameter()]
        [string]$ScanLog = ""
    )

    if ([string]::IsNullOrWhiteSpace($ScanLog)) {
        return $null
    }

    $patterns = @(
        "open\s+(?:the\s+page\s+)?(?<Url>https://\S+)\s+and\s+enter\s+the\s+code\s+(?<Code>[A-Z0-9\-]+)",
        "(?<Url>https://login\.microsoft\.com/device).*?(?<Code>[A-Z0-9\-]{6,})",
        "(?<Url>https://microsoft\.com/devicelogin).*?(?<Code>[A-Z0-9\-]{6,})"
    )

    foreach ($pattern in $patterns) {
        $challengeMatches = [regex]::Matches($ScanLog, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($challengeMatches.Count -gt 0) {
            $match = $challengeMatches[$challengeMatches.Count - 1]
            return [pscustomobject]@{
                Url = $match.Groups["Url"].Value
                Code = $match.Groups["Code"].Value
                Message = "Microsoft sign-in required. Open the link and enter the code."
            }
        }
    }

    return $null
}

function Test-UiScanRequest {
    param(
        # The Origin header exactly as received, or $null when the request has none.
        [Parameter()]
        [AllowNull()]
        [object]$Origin,

        # The Content-Type header exactly as received, or $null when the request has none.
        [Parameter()]
        [AllowNull()]
        [object]$ContentType,

        [Parameter(Mandatory)]
        [int]$Port
    )

    # A web page on another site can make the browser send a POST to this local server.
    # So a request that names an origin must name this server's own, and the body must be declared as JSON,
    # which a page on another site cannot send without a cross-origin check that this server does not answer.
    # The server's own origin has the port in it, except on port 80, where a browser leaves the port out.
    # Ordinal comparison, because -eq and -in ignore soft hyphens and zero-width characters.
    $ownOrigins = @("http://localhost:$Port")
    if ($Port -eq 80) { $ownOrigins += "http://localhost" }
    if ($null -ne $Origin) {
        $originText = ([string]$Origin).Trim()
        $isOwnOrigin = $false
        foreach ($ownOrigin in $ownOrigins) {
            if ([string]::Equals($ownOrigin, $originText, [System.StringComparison]::OrdinalIgnoreCase)) { $isOwnOrigin = $true }
        }
        if (-not $isOwnOrigin) {
            return [pscustomobject]@{ Allowed = $false; Reason = "The request came from a different origin." }
        }
    }

    $mediaType = ([string]$ContentType -split ";")[0].Trim()
    if (-not [string]::Equals($mediaType, "application/json", [System.StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Allowed = $false; Reason = "The request must have Content-Type application/json." }
    }

    return [pscustomobject]@{ Allowed = $true; Reason = "" }
}

function Test-UiScanRunning {
    if ($script:ScanJob -and $script:ScanJob.State -in @("Running", "NotStarted")) {
        return $true
    }

    return $false
}

function Start-UiScan {
    if (Test-UiScanRunning) {
        return [pscustomobject]@{
            Started = $false
            Running = $true
            Message = "A scan is already running."
        }
    }

    "Starting metadata-only scan at $(Get-Date -Format o)" | Set-Content -LiteralPath $scanLogPath -Encoding UTF8
    $script:ScanJob = Start-Job -Name "M365ForwardingMonitorScan" -ArgumentList $resolvedProjectRoot, $scanLogPath, $scanStatusPath -ScriptBlock {
        param(
            [string]$Root,
            [string]$LogPath,
            [string]$StatusPath
        )

        $ErrorActionPreference = "Continue"
        $startedAt = (Get-Date).ToString("o")
        [pscustomobject]@{
            Running = $true
            StartedAt = $startedAt
            FinishedAt = $null
            ExitCode = $null
            Message = "Scan running. Complete Microsoft device-code prompts if shown below."
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatusPath -Encoding UTF8

        try {
            Set-Location -LiteralPath $Root
            $authVolume = "m365-forwarding-monitor_m365-ps-auth"
            & docker volume create $authVolume | Out-Null
            $containerName = "m365-forwarding-monitor-scan-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
            $dockerArgs = @(
                "run", "--rm",
                "--name", $containerName,
                "-e", "M365_SETTINGS_PATH=/app/config/settings.json",
                "-e", "M365_APPROVED_EXCEPTIONS_PATH=/app/config/approved-exceptions.csv",
                "-e", "M365_USE_DEVICE_AUTH=true",
                "-e", "M365_CERT_PASSWORD",
                "-v", "$Root/config:/app/config:ro",
                "-v", "$Root/output:/app/output",
                "-v", "${authVolume}:/root/.local/share/powershell",
                "m365-forwarding-monitor:local"
            )

            "Command: docker $($dockerArgs -join ' ')" | Add-Content -LiteralPath $LogPath
            "Privacy: metadata-only. No email bodies, subjects, previews, attachments, or message content are collected." | Add-Content -LiteralPath $LogPath
            & docker @dockerArgs *>&1 | Tee-Object -LiteralPath $LogPath -Append
            $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }
            "Finished at $(Get-Date -Format o) with exit code $exitCode" | Add-Content -LiteralPath $LogPath

            [pscustomobject]@{
                Running = $false
                StartedAt = $startedAt
                FinishedAt = (Get-Date).ToString("o")
                ExitCode = $exitCode
                Message = if ($exitCode -eq 0) { "Scan complete." } else { "Scan finished with errors. Check scan log and errors.log." }
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatusPath -Encoding UTF8
        }
        catch {
            "Scan failed: $($_.Exception.Message)" | Add-Content -LiteralPath $LogPath
            [pscustomobject]@{
                Running = $false
                StartedAt = $startedAt
                FinishedAt = (Get-Date).ToString("o")
                ExitCode = 1
                Message = $_.Exception.Message
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatusPath -Encoding UTF8
        }
    }

    return [pscustomobject]@{
        Started = $true
        Running = $true
        Message = "Scan started. Watch the log for Microsoft device-code instructions."
    }
}

function Get-UiStatus {
    $summary = Get-UiSummary
    $scanLog = Get-UiFileTail -Path $scanLogPath -LineCount 160
    $scanStatus = $null
    if (Test-Path -LiteralPath $scanStatusPath) {
        try { $scanStatus = Get-Content -LiteralPath $scanStatusPath -Raw | ConvertFrom-Json } catch { $scanStatus = $null }
    }

    return [pscustomobject]@{
        Running = Test-UiScanRunning
        DashboardExists = Test-Path -LiteralPath $dashboardPath
        DashboardUpdatedAt = if (Test-Path -LiteralPath $dashboardPath) { (Get-Item -LiteralPath $dashboardPath).LastWriteTime.ToString("o") } else { $null }
        Summary = $summary
        ScanStatus = $scanStatus
        AuthChallenge = Get-UiAuthChallenge -ScanLog $scanLog
        ScanLog = $scanLog
        ErrorLog = Get-UiFileTail -Path $errorsPath -LineCount 80
    }
}

function Get-UiIndexHtml {
    return @'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M365 Forwarding Monitor Control</title>
  <style>
    :root { color-scheme: light; --bg:#f5f6f8; --panel:#fff; --ink:#1f2933; --muted:#667085; --line:#d7dde5; --accent:#225ea8; --danger:#b42318; --good:#087443; --notice:#fff8e6; --noticeLine:#f3c76d; }
    body { margin:0; font-family:"Segoe UI", Arial, sans-serif; color:var(--ink); background:var(--bg); }
    header { padding:20px 26px; background:#fff; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:center; justify-content:space-between; flex-wrap:wrap; }
    h1 { margin:0; font-size:22px; letter-spacing:0; }
    .privacy { margin:6px 0 0; color:var(--muted); font-size:13px; max-width:980px; line-height:1.4; }
    button { border:0; background:var(--accent); color:#fff; padding:10px 14px; border-radius:6px; font-weight:650; cursor:pointer; }
    button[disabled] { opacity:.55; cursor:not-allowed; }
    main { padding:18px 26px 28px; display:grid; gap:16px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .panel h2 { margin:0; padding:12px 14px; font-size:15px; border-bottom:1px solid var(--line); }
    .status { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; padding:14px; }
    .card { border:1px solid #edf0f4; border-radius:8px; padding:12px; min-height:62px; }
    .card span { display:block; color:var(--muted); font-size:12px; margin-bottom:8px; }
    .card strong { display:block; font-size:24px; }
    .row { padding:12px 14px; color:var(--muted); font-size:14px; border-top:1px solid #edf0f4; }
    pre { margin:0; padding:14px; max-height:260px; overflow:auto; background:#101828; color:#e7edf7; font-size:12px; line-height:1.45; white-space:pre-wrap; }
    iframe { width:100%; height:760px; border:0; background:#fff; display:block; }
    .error pre { background:#2b1214; }
    .small { font-size:12px; color:var(--muted); }
    .auth { border-color:var(--noticeLine); background:var(--notice); }
    .authBody { padding:16px; display:grid; gap:12px; }
    .authCode { font-family:"SFMono-Regular", Consolas, monospace; font-size:34px; font-weight:750; letter-spacing:.08em; }
    .authLink { color:#fff; background:var(--good); text-decoration:none; padding:10px 14px; border-radius:6px; font-weight:650; display:inline-block; width:max-content; }
    .hidden { display:none; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>M365 Forwarding Monitor</h1>
      <p class="privacy">Local-only control page. Metadata-only: no email bodies, subjects, previews, attachment contents, or individual message content are collected or displayed.</p>
    </div>
    <button id="scanButton">Run Scan Now</button>
  </header>
  <main>
    <section class="panel">
      <h2>Status</h2>
      <div class="status" id="cards"></div>
      <div class="row" id="message">Loading...</div>
    </section>
    <section class="panel auth hidden" id="authPanel">
      <h2>Microsoft Login Code</h2>
      <div class="authBody">
        <div>Open the Microsoft device login page and enter this code. Complete this before the prompt times out.</div>
        <div class="authCode" id="authCode"></div>
        <a class="authLink" id="authLink" href="https://login.microsoft.com/device" target="_blank" rel="noreferrer">Open Microsoft Login</a>
        <div class="small">The code is generated by Microsoft for this scan. The monitor never asks for your password or MFA code.</div>
      </div>
    </section>
    <section class="panel">
      <h2>Scan Log</h2>
      <pre id="scanLog">No scan log yet.</pre>
    </section>
    <section class="panel error">
      <h2>Errors</h2>
      <pre id="errorLog">No errors logged.</pre>
    </section>
    <section class="panel">
      <h2>Dashboard</h2>
      <iframe id="dashboardFrame" src="/dashboard.html"></iframe>
    </section>
  </main>
  <script>
    const scanButton = document.getElementById('scanButton');
    const cards = document.getElementById('cards');
    const message = document.getElementById('message');
    const scanLog = document.getElementById('scanLog');
    const errorLog = document.getElementById('errorLog');
    const dashboardFrame = document.getElementById('dashboardFrame');
    const authPanel = document.getElementById('authPanel');
    const authCode = document.getElementById('authCode');
    const authLink = document.getElementById('authLink');

    function valueOrZero(value) { return value ?? 0; }
    function renderCards(summary, running, updatedAt) {
      const items = [
        ['Scan running', running ? 'Yes' : 'No'],
        ['Users scanned', valueOrZero(summary?.TotalUsersScanned)],
        ['High/Critical', valueOrZero(summary?.HighCriticalRiskCount)],
        ['Abnormal outbound', valueOrZero(summary?.AbnormalOutboundCount)],
        ['Above average', valueOrZero(summary?.AboveBaselineOutboundCount)],
        ['Updated', updatedAt ? new Date(updatedAt).toLocaleString() : 'Not yet']
      ];
      cards.innerHTML = items.map(([label, value]) => `<div class="card"><span>${label}</span><strong>${value}</strong></div>`).join('');
    }

    async function refreshStatus() {
      const response = await fetch('/api/status', { cache: 'no-store' });
      const status = await response.json();
      renderCards(status.Summary, status.Running, status.DashboardUpdatedAt);
      scanButton.disabled = status.Running;
      message.textContent = status.ScanStatus?.Message || (status.DashboardExists ? 'Dashboard ready.' : 'Run a scan to generate the dashboard.');
      scanLog.textContent = status.ScanLog || 'No scan log yet.';
      errorLog.textContent = status.ErrorLog || 'No errors logged.';
      if (status.AuthChallenge?.Code) {
        authPanel.classList.remove('hidden');
        authCode.textContent = status.AuthChallenge.Code;
        authLink.href = status.AuthChallenge.Url || 'https://login.microsoft.com/device';
      } else {
        authPanel.classList.add('hidden');
        authCode.textContent = '';
      }
      if (!status.Running && status.DashboardExists) {
        dashboardFrame.src = '/dashboard.html?ts=' + Date.now();
      }
    }

    scanButton.addEventListener('click', async () => {
      scanButton.disabled = true;
      message.textContent = 'Starting scan...';
      await fetch('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      await refreshStatus();
    });

    refreshStatus();
    setInterval(refreshStatus, 3000);
  </script>
</body>
</html>
'@
}

$listener = [System.Net.HttpListener]::new()
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "M365 Forwarding Monitor UI running at $prefix"
Write-Host "Press Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $path = $context.Request.Url.AbsolutePath
        $method = $context.Request.HttpMethod

        try {
            switch -Regex ($path) {
                "^/$" {
                    Send-UiResponse -Context $context -ContentType "text/html; charset=utf-8" -Body (Get-UiIndexHtml)
                    break
                }
                "^/index\.html$" {
                    Send-UiResponse -Context $context -ContentType "text/html; charset=utf-8" -Body (Get-UiIndexHtml)
                    break
                }
                "^/dashboard\.html$" {
                    Send-UiFile -Context $context -Path $dashboardPath -ContentType "text/html; charset=utf-8"
                    break
                }
                "^/api/status$" {
                    Send-UiResponse -Context $context -ContentType "application/json; charset=utf-8" -Body (ConvertTo-JsonResponse -Value (Get-UiStatus))
                    break
                }
                "^/api/scan$" {
                    if ($method -ne "POST") {
                        Send-UiResponse -Context $context -StatusCode 405 -Body "Method not allowed."
                    }
                    else {
                        $scanRequest = Test-UiScanRequest -Origin $context.Request.Headers["Origin"] -ContentType $context.Request.ContentType -Port $Port
                        if (-not $scanRequest.Allowed) {
                            Send-UiResponse -Context $context -StatusCode 403 -Body "Forbidden. $($scanRequest.Reason)"
                        }
                        else {
                            Send-UiResponse -Context $context -ContentType "application/json; charset=utf-8" -Body (ConvertTo-JsonResponse -Value (Start-UiScan))
                        }
                    }
                    break
                }
                "^/favicon\.ico$" {
                    Send-UiResponse -Context $context -StatusCode 204 -Body ""
                    break
                }
                default {
                    Send-UiResponse -Context $context -StatusCode 404 -Body "Not found."
                }
            }
        }
        catch {
            Send-UiResponse -Context $context -StatusCode 500 -Body $_.Exception.Message
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
