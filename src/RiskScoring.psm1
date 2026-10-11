Set-StrictMode -Version Latest

# M365 Forwarding Monitor is metadata-only. It never reads or stores email bodies,
# subjects, previews, attachment contents, or individual message content.

function Write-M365MonitorError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [object]$ErrorRecord,

        [Parameter()]
        [string]$OutputPath = "./output"
    )

    try {
        if (-not (Test-Path -LiteralPath $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }

        $timestamp = (Get-Date).ToString("o")
        $detail = if ($ErrorRecord) { $ErrorRecord.ToString() } else { "" }
        Add-Content -Path (Join-Path $OutputPath "errors.log") -Value "[$timestamp] $Message $detail"
    }
    catch {
        Write-Warning "Unable to write to errors.log: $($_.Exception.Message)"
    }
}

function Invoke-M365CallWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$OperationName,

        [Parameter()]
        [string]$OutputPath = "./output",

        [Parameter()]
        [int]$MaxAttempts = 3,

        [Parameter()]
        [switch]$ThrowOnFailure
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $statusCode = $null
            $response = $null
            if ($_.Exception.PSObject.Properties.Name -contains "Response") {
                $response = $_.Exception.Response
            }
            if ($response -and $response.PSObject.Properties.Name -contains "StatusCode" -and $response.StatusCode) {
                $statusCode = [int]$response.StatusCode
            }

            $isThrottle = $statusCode -eq 429 -or $statusCode -eq 503 -or $_.Exception.Message -match "throttl|too many requests|temporar"
            Write-M365MonitorError -Message "$OperationName failed on attempt $attempt." -ErrorRecord $_ -OutputPath $OutputPath

            if ($attempt -lt $MaxAttempts -and $isThrottle) {
                $delaySeconds = [Math]::Min(60, [Math]::Pow(2, $attempt) * 5)
                Start-Sleep -Seconds $delaySeconds
                continue
            }

            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds 2
                continue
            }

            Write-Warning "$OperationName failed. See errors.log for details."
            if ($ThrowOnFailure) {
                throw "$OperationName failed after $MaxAttempts attempt(s). See errors.log for details."
            }
            return $null
        }
    }
}

function Get-M365TargetDomain {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Target
    )

    if ([string]::IsNullOrWhiteSpace($Target)) {
        return $null
    }

    $clean = $Target.Trim()
    if ($clean -match "SMTP:([^>\s]+@[^>\s]+)") {
        $clean = $Matches[1]
    }
    elseif ($clean -match "([^<>\s]+@[^<>\s]+)") {
        $clean = $Matches[1]
    }

    $mailAddress = $null
    if ([System.Net.Mail.MailAddress]::TryCreate($clean, [ref]$mailAddress)) {
        return $mailAddress.Host.ToLowerInvariant()
    }

    if ($clean -like "*@*") {
        return ($clean.Split("@")[-1]).Trim(">").ToLowerInvariant()
    }

    return $null
}

function Test-M365InternalDomain {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string[]]$InternalDomains = @()
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $false
    }

    $normalized = $Domain.ToLowerInvariant()
    return @($InternalDomains | ForEach-Object { $_.ToLowerInvariant() }) -contains $normalized
}

function Test-M365PersonalDomain {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string[]]$PersonalDomains = @()
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $false
    }

    $normalized = $Domain.ToLowerInvariant()
    return @($PersonalDomains | ForEach-Object { $_.ToLowerInvariant() }) -contains $normalized
}

function Get-M365TargetAddress {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Target
    )

    # Returns the lower-case mail address inside a forwarding target, or $null if there is none.
    # An address in angle brackets wins over any display text in front of it.
    if ([string]::IsNullOrWhiteSpace($Target)) {
        return $null
    }

    $clean = $Target.Trim()
    if ($clean -match "SMTP:([^>\s]+@[^>\s]+)") {
        $clean = $Matches[1]
    }
    elseif ($clean -match "<([^<>\s]+@[^<>\s]+)>") {
        $clean = $Matches[1]
    }
    elseif ($clean -match "([^<>\s]+@[^<>\s]+)") {
        $clean = $Matches[1]
    }

    $mailAddress = $null
    if ([System.Net.Mail.MailAddress]::TryCreate($clean, [ref]$mailAddress)) {
        return $mailAddress.Address.ToLowerInvariant()
    }

    if ($clean -like "*@*") {
        return $clean.ToLowerInvariant()
    }

    return $null
}

function Test-M365ApprovedException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [string]$Target,

        [Parameter()]
        [object[]]$ApprovedExceptions = @()
    )

    if (-not $ApprovedExceptions -or [string]::IsNullOrWhiteSpace($Target)) {
        return $false
    }

    $today = (Get-Date).Date
    $normalizedUser = $UserPrincipalName.ToLowerInvariant()
    $normalizedTarget = $Target.Trim().ToLowerInvariant()
    $targetAddress = Get-M365TargetAddress -Target $Target
    $targetDomain = if ($targetAddress) {
        $targetAddress.Substring($targetAddress.LastIndexOf("@") + 1)
    }
    else {
        Get-M365TargetDomain -Target $Target
    }

    foreach ($exception in $ApprovedExceptions) {
        $exceptionUser = [string]$exception.UserPrincipalName
        $exceptionTarget = [string]$exception.ApprovedTarget
        if ([string]::IsNullOrWhiteSpace($exceptionUser) -or [string]::IsNullOrWhiteSpace($exceptionTarget)) {
            continue
        }

        if ($exceptionUser.ToLowerInvariant() -ne $normalizedUser) {
            continue
        }

        # A blank or whitespace-only ExpirationDate means the exception does not expire.
        # Any other value must be exactly yyyy-MM-dd (a date, no time, no offset), read the same way
        # under every culture. A value in any other form fails closed: the exception is skipped,
        # so it never approves anything. The exception is valid through the end of its expiry day.
        $expirationText = [string]$exception.ExpirationDate
        if (-not [string]::IsNullOrWhiteSpace($expirationText)) {
            $expires = [datetime]::MinValue
            $isReadable = [datetime]::TryParseExact(
                $expirationText,
                "yyyy-MM-dd",
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None,
                [ref]$expires)
            if (-not $isReadable -or $expires.Date -lt $today) {
                continue
            }
        }

        $normalizedExceptionTarget = $exceptionTarget.Trim().ToLowerInvariant()
        if ($normalizedExceptionTarget -in @("*", "any")) {
            return $true
        }

        if ($normalizedExceptionTarget.Contains("@")) {
            # An ApprovedTarget with an at sign approves that exact address and nothing else.
            $exceptionAddress = Get-M365TargetAddress -Target $exceptionTarget
            if ($exceptionAddress -and $targetAddress -and $exceptionAddress -eq $targetAddress) {
                return $true
            }
            continue
        }

        # No at sign: a bare domain. It approves any address at exactly that domain, not its subdomains.
        # A target that has no address in it (for example a recipient identity) must match the text exactly.
        if ($targetDomain) {
            if ($targetDomain -eq $normalizedExceptionTarget) {
                return $true
            }
        }
        elseif ($normalizedTarget -eq $normalizedExceptionTarget) {
            return $true
        }
    }

    return $false
}

function Get-M365ForwardingRiskLevel {
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$RuleEnabled = $true,

        [Parameter()]
        [bool]$IsExternal,

        [Parameter()]
        [bool]$IsPersonalDomain,

        [Parameter()]
        [bool]$ApprovedException
    )

    if ($ApprovedException) { return "Exception" }
    if (-not $RuleEnabled) { return "Low" }
    if ($IsExternal -and $IsPersonalDomain) { return "Critical" }
    if ($IsExternal) { return "High" }
    return "Low"
}

function Get-M365OutboundRiskLevel {
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$ExternalSentCount,

        [Parameter()]
        [int]$AfterHoursCount,

        [Parameter()]
        [nullable[double]]$BaselineAverage,

        [Parameter()]
        [int]$BaselineSampleCount = 0,

        [Parameter()]
        [bool]$IsAboveBaseline,

        [Parameter(Mandatory)]
        [object]$Settings
    )

    $critical = [int]$Settings.OutboundCriticalThreshold
    $warning = [int]$Settings.OutboundWarningThreshold
    $attention = if ($Settings.PSObject.Properties.Name -contains "OutboundAttentionThreshold") {
        [int]$Settings.OutboundAttentionThreshold
    }
    else {
        20
    }
    $minimumSamples = if ($Settings.PSObject.Properties.Name -contains "BaselineMinimumSamples") {
        [int]$Settings.BaselineMinimumSamples
    }
    else {
        3
    }
    $afterHoursWarning = if ($Settings.PSObject.Properties.Name -contains "AfterHoursWarningThreshold") {
        [int]$Settings.AfterHoursWarningThreshold
    }
    else {
        [Math]::Max(10, [Math]::Ceiling($warning / 4))
    }

    if ($ExternalSentCount -ge $critical) { return "Critical" }
    if ($ExternalSentCount -ge $warning) { return "Medium" }
    if ($ExternalSentCount -ge $attention -and $BaselineSampleCount -lt $minimumSamples) { return "Medium" }
    if ($ExternalSentCount -ge $attention -and $IsAboveBaseline) { return "Medium" }
    if ($AfterHoursCount -ge $afterHoursWarning) { return "Medium" }
    return "Low"
}

function Protect-M365CsvText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    # Spreadsheet programs read a cell that starts with = + - @ tab, carriage return or line feed as a
    # formula. A leading apostrophe makes the cell plain text. Line breaks inside a cell become one space.
    if ($Text -match '^[=+\-@\t\r\n]') { $Text = "'" + $Text }
    return ($Text -replace '[\r\n]+', ' ')
}

function ConvertTo-M365CsvSafeValue {
    [CmdletBinding()]
    param([Parameter()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [array]) {
        $parts = foreach ($item in $Value) {
            $safeItem = ConvertTo-M365CsvSafeValue -Value $item
            if ($null -eq $safeItem) { '' } else { [string]$safeItem }
        }
        return ($parts -join "; ")
    }
    if ($Value -is [string]) { return (Protect-M365CsvText -Text $Value) }
    return $Value
}

Export-ModuleMember -Function @(
    "Write-M365MonitorError",
    "Invoke-M365CallWithRetry",
    "Get-M365TargetDomain",
    "Test-M365InternalDomain",
    "Test-M365PersonalDomain",
    "Test-M365ApprovedException",
    "Get-M365ForwardingRiskLevel",
    "Get-M365OutboundRiskLevel",
    "ConvertTo-M365CsvSafeValue"
)
