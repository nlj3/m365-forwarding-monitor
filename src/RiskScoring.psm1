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
        Add-Content -LiteralPath (Join-Path $OutputPath "errors.log") -Value "[$timestamp] $Message $detail"
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
        [switch]$ThrowOnFailure,

        # An error whose text (message or error details) matches this pattern is not retried and is not logged
        # as a failure. The original error is rethrown so the caller can tell it from a call that gave up.
        [Parameter()]
        [string]$NoRetryPattern,

        # The same as NoRetryPattern, decided by a script block that gets the error record and returns $true for an
        # error that is an answer rather than a failure. It can look at the error's type and category, not only its text.
        [Parameter()]
        [scriptblock]$NoRetryWhen
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($NoRetryPattern) {
                $errorDetails = if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { "" }
                if ("$($_.Exception.Message) $errorDetails" -match $NoRetryPattern) {
                    throw $_
                }
            }
            if ($NoRetryWhen -and (& $NoRetryWhen $_)) {
                throw $_
            }

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

function Get-M365TargetAddress {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Target
    )

    # Returns the lower-case mail address a forwarding target points at, or $null when the text does not
    # name exactly one address. A target that is unclear is never approved and is treated as external.
    if ([string]::IsNullOrWhiteSpace($Target)) {
        return $null
    }

    $text = $Target.Trim()
    if ($text.StartsWith("smtp:", [System.StringComparison]::OrdinalIgnoreCase)) {
        $text = $text.Substring(5).Trim()
    }

    # Exactly one at sign. Two or more mean two addresses, a quoted local part that holds an address, or
    # display text that holds one. Whichever it is, the real destination cannot be told from the text.
    if (($text.Length - $text.Replace("@", "").Length) -ne 1) {
        return $null
    }

    $mailAddress = $null
    if ([System.Net.Mail.MailAddress]::TryCreate($text, [ref]$mailAddress)) {
        return $mailAddress.Address.ToLowerInvariant()
    }

    # The angle-bracket form, only when the whole string did not parse.
    if ($text -match "<([^<>\s@]+@[^<>\s@]+)>\s*$" -and [System.Net.Mail.MailAddress]::TryCreate($Matches[1], [ref]$mailAddress)) {
        return $mailAddress.Address.ToLowerInvariant()
    }

    return $null
}

function Get-M365TargetDomain {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Target
    )

    $address = Get-M365TargetAddress -Target $Target
    if (-not $address) {
        return $null
    }

    return $address.Substring($address.LastIndexOf("@") + 1)
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

    # Ordinal comparison: the -eq and -contains operators ignore soft hyphens and zero-width characters,
    # so a domain with one hidden in it would match a listed domain.
    foreach ($candidate in $InternalDomains) {
        if ([string]::Equals($candidate, $Domain, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
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

    foreach ($candidate in $PersonalDomains) {
        if ([string]::Equals($candidate, $Domain, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-M365ExceptionExpiry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Exception
    )

    # State is None (no expiry), Valid (Date holds the last day the exception counts) or Unreadable.
    # A blank or whitespace-only ExpirationDate means the exception does not expire. Any other value must be
    # exactly yyyy-MM-dd (a date, no time, no offset), read the same way under every culture.
    $text = [string]$Exception.ExpirationDate
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{ State = "None"; Date = $null }
    }

    $date = [datetime]::MinValue
    $isReadable = [datetime]::TryParseExact(
        $text,
        "yyyy-MM-dd",
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None,
        [ref]$date)

    if ($isReadable) {
        return [pscustomobject]@{ State = "Valid"; Date = $date }
    }

    return [pscustomobject]@{ State = "Unreadable"; Date = $null }
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

    $ordinal = [System.StringComparison]::OrdinalIgnoreCase
    $today = (Get-Date).Date
    $targetText = $Target.Trim()
    $targetAddress = Get-M365TargetAddress -Target $Target
    $targetDomain = if ($targetAddress) {
        $targetAddress.Substring($targetAddress.LastIndexOf("@") + 1)
    }
    else {
        $null
    }

    foreach ($exception in $ApprovedExceptions) {
        $exceptionUser = [string]$exception.UserPrincipalName
        $exceptionTarget = ([string]$exception.ApprovedTarget).Trim()
        if ([string]::IsNullOrWhiteSpace($exceptionUser) -or [string]::IsNullOrWhiteSpace($exceptionTarget)) {
            continue
        }

        if (-not [string]::Equals($exceptionUser, $UserPrincipalName, $ordinal)) {
            continue
        }

        # An exception whose date cannot be read fails closed: it is skipped, so it never approves anything.
        # It is valid through the end of its expiry day.
        $expiry = Get-M365ExceptionExpiry -Exception $exception
        if ($expiry.State -eq "Unreadable") {
            continue
        }
        if ($expiry.State -eq "Valid" -and $expiry.Date.Date -lt $today) {
            continue
        }

        # All comparisons below are ordinal, so a soft hyphen or zero-width character never makes two values equal.
        if ([string]::Equals($exceptionTarget, "*", $ordinal) -or [string]::Equals($exceptionTarget, "any", $ordinal)) {
            return $true
        }

        if ($exceptionTarget.Contains("@")) {
            # An ApprovedTarget with an at sign approves that exact address and nothing else.
            $exceptionAddress = Get-M365TargetAddress -Target $exceptionTarget
            if ($exceptionAddress -and $targetAddress -and [string]::Equals($exceptionAddress, $targetAddress, $ordinal)) {
                return $true
            }
            continue
        }

        # No at sign: a bare domain. It approves any address at exactly that domain, not its subdomains.
        # A target that holds no address (for example a recipient identity) must match the text exactly.
        if ($targetDomain) {
            if ([string]::Equals($targetDomain, $exceptionTarget, $ordinal)) {
                return $true
            }
        }
        elseif ([string]::Equals($targetText, $exceptionTarget, $ordinal)) {
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

function Get-M365NoMailboxPattern {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Mailbox", "InboxRules")]
        [string]$Source
    )

    # What the two calls say when the account has no mailbox, as opposed to a call that failed.
    # Exchange: the identity could not be found. Exchange Online puts the exception type name in the message
    # ("Ex6F9304|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|..."), and that part is not
    # translated. Graph: MailboxNotEnabledForRESTAPI or ErrorItemNotFound.
    if ($Source -eq "Mailbox") {
        return "couldn.t be found|could not be found|ManagementObjectNotFoundException"
    }

    return "MailboxNotEnabledForRESTAPI|ErrorItemNotFound"
}

function Test-M365NoMailboxError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter(Mandatory)]
        [ValidateSet("Mailbox", "InboxRules")]
        [string]$Source
    )

    $errorDetails = if ($ErrorRecord.ErrorDetails) { [string]$ErrorRecord.ErrorDetails.Message } else { "" }
    if ("$($ErrorRecord.Exception.Message) $errorDetails" -match (Get-M365NoMailboxPattern -Source $Source)) {
        return $true
    }
    if ($Source -ne "Mailbox") {
        # Graph answers with error codes, which are not translated, so the text is enough.
        return $false
    }

    # Exchange translates its messages, so a localized "could not be found" is matched by the error's type or
    # category instead. A command that is not loaded is ObjectNotFound too; that is a failure, never "no mailbox".
    $exceptions = [System.Collections.Generic.List[System.Exception]]::new()
    for ($exception = $ErrorRecord.Exception; $null -ne $exception; $exception = $exception.InnerException) {
        $exceptions.Add($exception)
    }
    if (@($exceptions | Where-Object { $_ -is [System.Management.Automation.CommandNotFoundException] }).Count -gt 0) {
        return $false
    }
    if (@($exceptions | Where-Object { $_.GetType().Name -eq "ManagementObjectNotFoundException" }).Count -gt 0) {
        return $true
    }
    if ([string]$ErrorRecord.CategoryInfo.Reason -eq "ManagementObjectNotFoundException" -or [string]$ErrorRecord.FullyQualifiedErrorId -match "ManagementObjectNotFoundException") {
        return $true
    }
    return $ErrorRecord.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound
}

function Get-M365BusinessHoursTimeZone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Settings
    )

    # BusinessHoursTimeZone is an IANA id (America/Chicago) or a Windows id (Central Standard Time).
    # When the key is missing or blank, the time zone of the computer running the scan is used.
    $zoneId = $null
    if ($Settings.PSObject.Properties.Name -contains "BusinessHoursTimeZone") {
        $zoneId = [string]$Settings.BusinessHoursTimeZone
    }

    if ([string]::IsNullOrWhiteSpace($zoneId)) {
        return [System.TimeZoneInfo]::Local
    }

    try {
        return [System.TimeZoneInfo]::FindSystemTimeZoneById($zoneId.Trim())
    }
    catch {
        throw "BusinessHoursTimeZone '$zoneId' is not a time zone this computer knows. Use an IANA id such as America/Chicago or a Windows id such as Central Standard Time."
    }
}

function Get-M365BusinessHour {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$Received,

        [Parameter(Mandatory)]
        [System.TimeZoneInfo]$TimeZone
    )

    # Message trace times are UTC. A time with no kind is taken as UTC; a local time is converted to UTC first.
    $utc = if ($Received.Kind -eq [System.DateTimeKind]::Local) {
        $Received.ToUniversalTime()
    }
    else {
        [datetime]::SpecifyKind($Received, [System.DateTimeKind]::Utc)
    }

    return [System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $TimeZone).Hour
}

function Protect-M365CsvText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    # Spreadsheet programs read a cell that starts with = + - @ tab, carriage return or line feed as a
    # formula. A leading apostrophe makes the cell plain text. Line breaks inside a cell become one space.
    if ($Text -match '^[=+\-@\t\r\n]') { $Text = "'" + $Text }
    return ($Text -replace '[\r\n]+', ' ')
}

function Write-M365TextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    # Writes UTF-8 text without a byte order mark and flushes it through to the disk before the file is closed.
    # Without the flush a file can be renamed into place while its content is still only in memory, and a crash or
    # power cut seconds later leaves it empty or full of zeros.
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
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
    "Get-M365TargetAddress",
    "Test-M365InternalDomain",
    "Test-M365PersonalDomain",
    "Test-M365ApprovedException",
    "Get-M365ExceptionExpiry",
    "Get-M365NoMailboxPattern",
    "Test-M365NoMailboxError",
    "Get-M365ForwardingRiskLevel",
    "Get-M365OutboundRiskLevel",
    "Get-M365BusinessHoursTimeZone",
    "Get-M365BusinessHour",
    "Write-M365TextFile",
    "ConvertTo-M365CsvSafeValue"
)
