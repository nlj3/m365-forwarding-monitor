[CmdletBinding()]
param(
    [Parameter()]
    [int]$Port = 8181
)

# M365 Forwarding Monitor local UI launcher.
# Metadata-only: the UI displays scan status and generated metadata reports only.
# It does not read or display email bodies, subjects, previews, attachments, or message content.

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $scriptRoot "src/Start-ForwardingMonitorUi.ps1") -ProjectRoot $scriptRoot -Port $Port
