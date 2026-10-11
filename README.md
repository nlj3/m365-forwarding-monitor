# Microsoft 365 Forwarding Monitor

Metadata-only Microsoft 365 forwarding monitoring for internal IT and security visibility.

This tool detects mailbox forwarding, inbox rules that forward or redirect, external and personal forwarding targets, and abnormal outbound email volume using metadata only. It generates local JSON/CSV output and a static HTML dashboard.

## Privacy First

This repo is intentionally metadata-only.

It does not request `Mail.Read` or `Mail.ReadWrite`. It does not read or store email bodies, message content, subjects, message previews, attachment contents, or individual message content.

## What It Does

- Lists enabled internal users with Microsoft Graph.
- Checks Exchange Online mailbox forwarding settings.
- Checks Graph inbox message rule forwarding actions:
  - `actions.forwardTo`
  - `actions.redirectTo`
  - `actions.forwardAsAttachmentTo`
- Counts outbound external message trace metadata with `Get-MessageTraceV2`.
- Builds a local metadata-only baseline of each sender's external outbound count over time.
- Flags attention events when a sender is over the configured count threshold, above their personal average, or sending unusual after-hours volume.
- Flags external forwarding, personal-domain forwarding, approved exceptions, and outbound volume anomalies.
- Writes local JSON/CSV metadata and a static dashboard.

## What It Intentionally Does Not Do

- Does not read email body text.
- Does not read or store subjects.
- Does not read attachment contents.
- Does not store message previews.
- Does not delete inbox rules.
- Does not disable forwarding.
- Does not modify tenant settings.
- Does not prove which individual messages were forwarded.
- Does not approve, deny, block, or enforce anything. Labels are for review only.

## Required PowerShell Modules

Run in PowerShell 7:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Minimum Permissions

Microsoft Graph delegated permissions:

- `User.Read.All`
- `MailboxSettings.Read`

Exchange Online role access:

- Ability to run `Get-Mailbox`.
- Ability to run `Get-MessageTraceV2`.

Do not grant `Mail.Read`, `Mail.ReadWrite`, or permissions that allow reading email content.

For unattended scheduled operation, use app-only certificate authentication instead of device-code login. See [UNATTENDED-AUTH.md](./UNATTENDED-AUTH.md).

## App Registration

1. In Microsoft Entra admin center, create an app registration.
2. Set supported account type to your tenant only.
3. Add delegated Microsoft Graph permissions:
   - `User.Read.All`
   - `MailboxSettings.Read`
4. Grant admin consent if your tenant requires it.
5. Copy the tenant ID into `config/settings.json`.

For interactive administrator runs, Microsoft Graph PowerShell can also prompt for consent using the listed scopes.

For fully automated runs, configure `AuthMode` as `AppOnlyCertificate` in `settings.json` and follow [UNATTENDED-AUTH.md](./UNATTENDED-AUTH.md).

## Setup

```powershell
cd /path/to/m365-forwarding-monitor
Copy-Item ./config/settings.example.json ./config/settings.json
Copy-Item ./config/approved-exceptions.example.csv ./config/approved-exceptions.csv
notepad ./config/settings.json
notepad ./config/approved-exceptions.csv
```

Update:

- `TenantId`
- `InternalDomains`
- `PersonalDomains`
- Thresholds and business hours
- `OutputPath`

Keep `PrivacyMode` set to `true`.

Approved exceptions are configured in `config/approved-exceptions.csv`. `ApprovedTarget` can be a specific address, a domain-matching address, or `*` for a user-wide exception. Use `*` sparingly, such as for an owner-approved exception.

Outbound attention settings are also configurable:

- `OutboundAttentionThreshold`: default `20`; flags lower-volume attention events while the baseline is still learning.
- `BaselineMultiplier`: default `2.5`; flags users whose external outbound count is at least this many times higher than their personal average.
- `BaselineMinimumSamples`: default `3`; number of prior runs before the baseline is considered established.
- `BaselineRetentionDays`: optional; default `90`.

## Run Manually

```powershell
cd /path/to/m365-forwarding-monitor/src
pwsh ./Invoke-ForwardingMonitor.ps1 `
  -SettingsPath ../config/settings.json `
  -ApprovedExceptionsPath ../config/approved-exceptions.csv
```

Output files are written to `output/` by default:

- `summary.json`
- `summary.csv`
- `forwarding-findings.json`
- `forwarding-findings.csv`
- `outbound-metadata-counts.json`
- `outbound-metadata-counts.csv`
- `outbound-baseline-history.json`
- `dashboard.html`
- `errors.log`

## Run With Docker

Docker runs the same metadata-only scripts in a PowerShell container. Config and output stay on the host through mounted folders.

```powershell
cd /path/to/m365-forwarding-monitor
Copy-Item ./config/settings.example.json ./config/settings.json
Copy-Item ./config/approved-exceptions.example.csv ./config/approved-exceptions.csv
notepad ./config/settings.json
```

Build the image:

```powershell
docker build -t m365-forwarding-monitor:local .
```

On Apple Silicon or other ARM hosts, Docker may run the PowerShell image through emulation. If Docker reports a platform mismatch, rebuild the image locally with `docker build -t m365-forwarding-monitor:local .`.

Run interactively with device-code authentication:

```powershell
docker run --rm -it `
  -v "${PWD}/config:/app/config:ro" `
  -v "${PWD}/output:/app/output" `
  -e M365_USE_DEVICE_AUTH=true `
  m365-forwarding-monitor:local
```

Or use Docker Compose:

```powershell
docker compose run --rm m365-forwarding-monitor
```

When prompted, complete the device-code sign-in in a browser. The container still requests only `User.Read.All` and `MailboxSettings.Read` for Graph and uses Exchange Online read-only detection commands.

If `settings.json` has `"AuthMode": "AppOnlyCertificate"`, the scan uses the configured certificate and does not prompt for a device code.

For repeated runs, the Compose file includes a named PowerShell auth volume:

```text
m365-ps-auth
```

This can reduce repeated sign-in prompts, depending on tenant policy and token lifetime. Protect the Docker host and volume because authentication cache material can be sensitive.

## Local Web Interface

Start the localhost-only control UI on port `8181`:

```powershell
pwsh ./Start-LocalDashboard.ps1 -Port 8181
```

Open:

```text
http://localhost:8181/
```

The page can run a scan, show Microsoft device-code login text in the scan log, show errors, and display the generated dashboard. It is still metadata-only and does not read or display email bodies, subjects, previews, attachment contents, or message content.

## Schedule With Windows Task Scheduler

Create a task that runs as a dedicated least-privilege admin account:

Program:

```text
pwsh.exe
```

Arguments:

```text
-NoProfile -ExecutionPolicy Bypass -File "C:\Path\m365-forwarding-monitor\src\Invoke-ForwardingMonitor.ps1" -SettingsPath "../config/settings.json" -ApprovedExceptionsPath "../config/approved-exceptions.csv"
```

Start in:

```text
C:\Path\m365-forwarding-monitor\src
```

Recommended schedule: every 4 to 24 hours, depending on tenant size and operational need.

## Review Output

Open `output/dashboard.html` in a browser. Review high and critical findings first:

- External mailbox forwarding
- Enabled inbox rules forwarding to external domains
- Personal-domain forwarding targets
- Abnormal outbound metadata counts

The dashboard displays no email content, subjects, previews, or attachments.

## Troubleshooting

- Check `output/errors.log`.
- For Docker, confirm `config/settings.json` exists before running the container.
- For Docker, use `docker compose run --rm m365-forwarding-monitor` so the device-code prompt is visible.
- Confirm the Microsoft Graph modules are installed.
- Confirm Exchange Online module version supports `Get-MessageTraceV2`.
- Confirm the signed-in account has permission for `Get-Mailbox` and message trace.
- Confirm `InternalDomains` includes all accepted internal domains.
- If Graph calls fail, verify `User.Read.All` and `MailboxSettings.Read` consent.

## Known Limitations

- Graph inbox rules show configured forwarding rules but do not prove how many emails were actually forwarded.
- Message trace provides outbound metadata counts, not perfect forwarded-email counts.
- Manual user forwards are difficult to distinguish from normal outbound sends without content or advanced security logs.
- The per-user average is based on outbound external metadata counts, not confirmed manual forward actions.
- Baselines need several scheduled runs before they become meaningful.
- This tool detects forwarding configuration risk and abnormal outbound volume; it is not an email content inspection tool.

## Optional Future Output

Version 1 writes local JSON/CSV and HTML only. A future version can add SharePoint List output for centralized review, but SharePoint is not required.
