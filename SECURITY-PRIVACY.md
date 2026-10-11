# Security and Privacy

M365 Forwarding Monitor is designed for metadata-only security visibility.

## Plain-English Privacy Promise

This tool does not read email bodies. It does not store subjects. It does not read attachment contents. It does not collect message previews. It does not store individual message content.

The tool only collects metadata needed to detect forwarding risk:

- User identity metadata.
- Mailbox forwarding configuration.
- Inbox rule forwarding targets.
- Sender and recipient address metadata from message trace.
- Counts of outbound external messages.
- Rolling per-sender outbound count averages.
- External recipient domains.
- Time-of-send metadata for after-hours counts.

## Permissions

Use least privilege.

Microsoft Graph delegated permissions:

- `User.Read.All`
- `MailboxSettings.Read`

Do not grant:

- `Mail.Read`
- `Mail.ReadWrite`
- Any permission intended for reading email bodies, subjects, attachments, or message content.

Exchange Online access is used for read-only detection commands:

- `Get-Mailbox`
- `Get-MessageTraceV2`

Version 1 does not modify the tenant, delete rules, disable forwarding, or change mailbox settings.

The tool does not approve, deny, block, or enforce forwarding behavior. Any exception or risk label is informational and intended for human review.

## Container Security

The Docker image contains PowerShell and the Microsoft Graph and Exchange Online PowerShell modules. It does not include tenant-specific config by default.

Recommended controls:

- Mount `config/` read-only.
- Mount `output/` only where reviewers need access.
- Do not bake `settings.json`, approved exceptions, output files, logs, or token caches into a custom image.
- Do not bake private certificates, PFX files, PEM keys, or certificate passwords into a custom image.
- Protect the Docker host and any named auth volumes.
- Rebuild the image periodically to receive updated PowerShell modules.

## Unattended Authentication

For scheduled production use, prefer certificate-based app-only authentication over device-code login.

Recommended controls:

- Use an Entra app registration dedicated to this monitor.
- Grant only `User.Read.All`, `MailboxSettings.Read`, and the Exchange Online app/RBAC permissions needed for read-only monitoring.
- Do not grant `Mail.Read` or `Mail.ReadWrite`.
- Store private certificate material outside source control.
- Rotate certificates on a defined schedule.

## Why Forwarding Monitoring Matters

Mailbox forwarding and inbox-rule forwarding are common data loss and account compromise paths. An attacker who gains access to a mailbox can create a forwarding rule to silently copy future messages to an outside account. A legitimate user can also create risky forwarding to personal email, which may violate policy or compliance expectations.

Monitoring forwarding configuration helps IT and security teams find this risk without inspecting email content.

## Output File Controls

The output is metadata-only, but it can still be sensitive because it contains user addresses, forwarding targets, external domains, and risk labels.

Recommended controls:

- Store output in a restricted folder.
- Limit access to IT/security reviewers with a business need.
- Do not publish the dashboard to a public web server.
- Keep the local control UI bound to localhost only.
- Do not email raw output broadly.
- Protect scheduled task credentials.
- Consider disk encryption on the monitoring host.
- Treat `ApprovedTarget` values of `*` as sensitive policy exceptions and review them periodically.

## Retention

Recommended retention for v1 local output:

- Keep daily outputs for 30 to 90 days.
- Keep `errors.log` for 30 days unless needed for troubleshooting.
- Remove expired approved exceptions from the CSV.
- Store longer retention only if approved by legal, privacy, and security leadership.

## Limitations

- Graph inbox rules show configured forwarding rules but do not prove how many emails were actually forwarded.
- Message trace provides outbound metadata counts, not perfect forwarded-email counts.
- Manual user forwards are difficult to distinguish from normal outbound sends without content or advanced security logs.
- Per-user averages are based on repeated metadata-only scans and need several runs before they are meaningful.
- This tool is meant to detect forwarding configuration risk and abnormal outbound volume, not to spy on email content.
