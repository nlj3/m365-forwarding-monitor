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
    $normalizedTarget = $Target.ToLowerInvariant()
    $targetDomain = Get-M365TargetDomain -Target $Target

    foreach ($exception in $ApprovedExceptions) {
        $exceptionUser = [string]$exception.UserPrincipalName
        $exceptionTarget = [string]$exception.ApprovedTarget
        if ([string]::IsNullOrWhiteSpace($exceptionUser) -or [string]::IsNullOrWhiteSpace($exceptionTarget)) {
            continue
        }

        if ($exceptionUser.ToLowerInvariant() -ne $normalizedUser) {
            continue
        }

        # A blank ExpirationDate means the exception does not expire. A date that cannot be read
        # fails closed: the exception is skipped instead of being approved indefinitely.
        $expirationText = [string]$exception.ExpirationDate
        if (-not [string]::IsNullOrWhiteSpace($expirationText)) {
            $expires = [datetime]::MinValue
            if (-not [datetime]::TryParse($expirationText, [ref]$expires) -or $expires.Date -lt $today) {
                continue
            }
        }

        $normalizedExceptionTarget = $exceptionTarget.ToLowerInvariant()
        if ($normalizedExceptionTarget -in @("*", "any")) {
            return $true
        }

        $exceptionDomain = Get-M365TargetDomain -Target $exceptionTarget
        if ($normalizedExceptionTarget -eq $normalizedTarget -or
            ($targetDomain -and $exceptionDomain -and $targetDomain -eq $exceptionDomain)) {
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
