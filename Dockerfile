# M365 Forwarding Monitor container image.
# Metadata-only: this image does not include tooling or permissions to read email
# bodies, subjects, previews, attachment contents, or individual message content.

FROM mcr.microsoft.com/powershell:7.4-debian-12

SHELL ["pwsh", "-NoLogo", "-NoProfile", "-Command"]

ENV POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

WORKDIR /app

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force -AllowClobber; \
    Install-Module ExchangeOnlineManagement -Scope AllUsers -Force -AllowClobber; \
    Get-InstalledModule Microsoft.Graph.Authentication,ExchangeOnlineManagement | Select-Object Name,Version

COPY . /app

ENTRYPOINT ["pwsh", "-NoLogo", "-NoProfile", "-File", "/app/docker-entrypoint.ps1"]
