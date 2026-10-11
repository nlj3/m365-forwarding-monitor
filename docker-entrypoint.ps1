[CmdletBinding()]
param()

# M365 Forwarding Monitor container entrypoint.
# Metadata-only: no email bodies, subjects, previews, attachment contents, or individual
# message content are read or stored. Detection only; no tenant settings are modified.

$ErrorActionPreference = "Stop"

$settingsPath = if ($env:M365_SETTINGS_PATH) { $env:M365_SETTINGS_PATH } else { "/app/config/settings.json" }
$exceptionsPath = if ($env:M365_APPROVED_EXCEPTIONS_PATH) { $env:M365_APPROVED_EXCEPTIONS_PATH } else { "/app/config/approved-exceptions.csv" }
$useDeviceAuth = $env:M365_USE_DEVICE_AUTH -match "^(1|true|yes)$"

if (-not (Test-Path -LiteralPath $settingsPath)) {
    throw "Missing settings file at $settingsPath. Copy config/settings.example.json to config/settings.json and mount ./config into the container."
}

& /app/src/Invoke-ForwardingMonitor.ps1 `
    -SettingsPath $settingsPath `
    -ApprovedExceptionsPath $exceptionsPath `
    -UseDeviceAuthentication:$useDeviceAuth
