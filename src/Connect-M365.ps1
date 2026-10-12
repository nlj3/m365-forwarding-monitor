# M365 Forwarding Monitor is metadata-only. It never requests Mail.Read,
# Mail.ReadWrite, or permissions that read email bodies, subjects, previews, or attachments.

function Get-M365SettingValue {
    param(
        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [object]$Default = $null
    )

    if ($Settings.PSObject.Properties.Name -contains $Name -and -not [string]::IsNullOrWhiteSpace([string]$Settings.$Name)) {
        return $Settings.$Name
    }

    return $Default
}

function Resolve-M365CertificatePath {
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath
    )

    if ([System.IO.Path]::IsPathRooted($CertificatePath)) {
        return $CertificatePath
    }

    return (Resolve-Path -LiteralPath $CertificatePath).Path
}

function Get-M365AutomationCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Settings
    )

    $certificatePath = Get-M365SettingValue -Settings $Settings -Name "CertificatePath"
    if ([string]::IsNullOrWhiteSpace([string]$certificatePath)) {
        throw "AuthMode AppOnlyCertificate requires CertificatePath in settings.json."
    }

    $resolvedCertificatePath = Resolve-M365CertificatePath -CertificatePath ([string]$certificatePath)
    if (-not (Test-Path -LiteralPath $resolvedCertificatePath)) {
        throw "Certificate file was not found at $resolvedCertificatePath."
    }

    $passwordEnvVar = [string](Get-M365SettingValue -Settings $Settings -Name "CertificatePasswordEnvVar" -Default "M365_CERT_PASSWORD")
    $certificatePassword = [Environment]::GetEnvironmentVariable($passwordEnvVar)
    $storageFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet

    if ([string]::IsNullOrEmpty($certificatePassword)) {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedCertificatePath, "", $storageFlags)
    }

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolvedCertificatePath, $certificatePassword, $storageFlags)
}

function Connect-M365Monitor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Settings,

        [Parameter()]
        [string]$OutputPath = "./output",

        [Parameter()]
        [switch]$UseDeviceAuthentication
    )

    Write-Host "Loading Microsoft Graph authentication module..."
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    Write-Host "Loading Exchange Online module..."
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $authMode = [string](Get-M365SettingValue -Settings $Settings -Name "AuthMode" -Default "DeviceCode")
    $useAppOnlyCertificate = $authMode -eq "AppOnlyCertificate"
    $scopes = @("User.Read.All", "MailboxSettings.Read")
    $certificate = $null
    $applicationClientId = [string](Get-M365SettingValue -Settings $Settings -Name "ApplicationClientId")
    $exchangeOrganization = [string](Get-M365SettingValue -Settings $Settings -Name "ExchangeOrganization")

    if ($useAppOnlyCertificate) {
        if ([string]::IsNullOrWhiteSpace($applicationClientId)) {
            throw "AuthMode AppOnlyCertificate requires ApplicationClientId in settings.json."
        }
        if ([string]::IsNullOrWhiteSpace($exchangeOrganization)) {
            throw "AuthMode AppOnlyCertificate requires ExchangeOrganization in settings.json, usually your .onmicrosoft.com domain."
        }
        Write-Host "Loading app-only certificate for unattended authentication..."
        $certificate = Get-M365AutomationCertificate -Settings $Settings
    }

    Invoke-M365CallWithRetry -OperationName "Connect-MgGraph" -OutputPath $OutputPath -MaxAttempts 1 -ThrowOnFailure -ScriptBlock {
        if ($useAppOnlyCertificate) {
            Write-Host "Connecting to Microsoft Graph with app-only certificate authentication."
            Connect-MgGraph -TenantId $Settings.TenantId -ClientId $applicationClientId -Certificate $certificate -NoWelcome -ErrorAction Stop | Out-Null
        }
        elseif ($UseDeviceAuthentication) {
            Write-Host "Connecting to Microsoft Graph. A device-code login prompt should appear next."
            Connect-MgGraph -TenantId $Settings.TenantId -Scopes $scopes -UseDeviceCode -NoWelcome -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "Connecting to Microsoft Graph."
            Connect-MgGraph -TenantId $Settings.TenantId -Scopes $scopes -NoWelcome -ErrorAction Stop | Out-Null
        }
    } | Out-Null

    $graphContext = Get-MgContext
    if (-not $graphContext) {
        throw "Microsoft Graph authentication did not complete. The scan cannot list users or inbox rules without Graph access."
    }

    Invoke-M365CallWithRetry -OperationName "Connect-ExchangeOnline" -OutputPath $OutputPath -MaxAttempts 1 -ThrowOnFailure -ScriptBlock {
        if ($useAppOnlyCertificate) {
            Write-Host "Connecting to Exchange Online with app-only certificate authentication."
            Connect-ExchangeOnline -Certificate $certificate -AppId $applicationClientId -Organization $exchangeOrganization -ShowBanner:$false -ErrorAction Stop | Out-Null
        }
        elseif ($UseDeviceAuthentication) {
            Write-Host "Connecting to Exchange Online. A device-code login prompt may appear next."
            Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "Connecting to Exchange Online."
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null
        }
    } | Out-Null
}
