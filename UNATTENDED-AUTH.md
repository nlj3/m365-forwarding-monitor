# Unattended App-Only Authentication

M365 Forwarding Monitor can run without device-code prompts by using Microsoft Entra app-only certificate authentication.

This is the recommended production mode for scheduled monitoring. It is still metadata-only and does not grant `Mail.Read` or `Mail.ReadWrite`.

## What You Create

- One Microsoft Entra app registration.
- One X.509 certificate.
- Graph application permissions:
  - `User.Read.All`
  - `MailboxSettings.Read`
- Exchange Online application permission:
  - `Exchange.ManageAsApp`
- Exchange RBAC rights that allow read-only mailbox configuration and message trace review.

Microsoft documents `MailboxSettings.Read` as the least-privileged application permission for listing inbox message rules:

```text
GET /users/{id | userPrincipalName}/mailFolders/inbox/messageRules
```

Microsoft also documents certificate-based app-only authentication for Exchange Online PowerShell.

## Why Certificate Instead Of Secret

Use a certificate, not a long-lived client secret.

Certificates are easier to rotate safely, are supported by both Microsoft Graph PowerShell and Exchange Online PowerShell, and avoid storing a reusable client secret in config files.

## Step 1: Create A Local Certificate

Create a folder for local cert material:

```bash
cd /path/to/m365-forwarding-monitor
mkdir -p ./config/certs
```

Create a private key and public certificate:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout ./config/certs/m365-forwarding-monitor.key \
  -out ./config/certs/m365-forwarding-monitor.cer \
  -days 365 \
  -subj "/CN=M365 Forwarding Monitor" \
  -nodes
```

Create a password-protected PFX for the container:

```bash
openssl pkcs12 -export \
  -out ./config/certs/m365-forwarding-monitor.pfx \
  -inkey ./config/certs/m365-forwarding-monitor.key \
  -in ./config/certs/m365-forwarding-monitor.cer
```

Keep the PFX private. Upload only the `.cer` public certificate to Microsoft Entra.

## Step 2: Create The App Registration

In Microsoft Entra admin center:

1. Go to **Applications > App registrations**.
2. Create a new app named `M365 Forwarding Monitor`.
3. Copy the **Application (client) ID**.
4. Open **Certificates & secrets > Certificates**.
5. Upload:

```text
config/certs/m365-forwarding-monitor.cer
```

## Step 3: Add Graph Application Permissions

In the app registration:

1. Open **API permissions**.
2. Add **Microsoft Graph > Application permissions**:
   - `User.Read.All`
   - `MailboxSettings.Read`
3. Click **Grant admin consent**.

Do not add `Mail.Read` or `Mail.ReadWrite`.

## Step 4: Add Exchange Online App Permission

In the app registration:

1. Open **API permissions**.
2. Add **APIs my organization uses**.
3. Search for **Office 365 Exchange Online**.
4. Add **Application permissions**:
   - `Exchange.ManageAsApp`
5. Click **Grant admin consent**.

## Step 5: Assign Exchange RBAC

The app also needs Exchange role access for the specific read-only commands used by this monitor:

- `Get-Mailbox`
- `Get-MessageTraceV2`

Microsoft's broad/simple option is assigning the app's service principal an Entra role such as **Exchange Administrator**, but that is not least-privilege.

The better production option is Exchange RBAC for Applications: create or use a role group with only the roles needed for read-only mailbox configuration and message tracking, then add the app service principal to that role group.

If you need the first run working quickly, use the broader role temporarily, verify the monitor, then reduce privileges.

## Step 6: Update settings.json

Edit:

```text
config/settings.json
```

Set:

```json
"AuthMode": "AppOnlyCertificate",
"ApplicationClientId": "YOUR-APP-CLIENT-ID",
"ExchangeOrganization": "contoso.onmicrosoft.com",
"CertificatePath": "/app/config/certs/m365-forwarding-monitor.pfx",
"CertificatePasswordEnvVar": "M365_CERT_PASSWORD"
```

## Step 7: Set The PFX Password Locally

Set the certificate password in your shell before starting the UI or running Docker:

```bash
export M365_CERT_PASSWORD='your-pfx-password'
```

Do not put the password in `settings.json`.

## Step 8: Run

Build once:

```bash
docker build -t m365-forwarding-monitor:local .
```

Start the local UI:

```bash
pwsh ./Start-LocalDashboard.ps1 -Port 8181
```

Open:

```text
http://localhost:8181/
```

Click **Run Scan Now**. In app-only mode, no Microsoft device code should appear.

## Scheduling

Once app-only auth works, schedule:

```bash
cd /path/to/m365-forwarding-monitor
docker run --rm \
  -e M365_SETTINGS_PATH=/app/config/settings.json \
  -e M365_APPROVED_EXCEPTIONS_PATH=/app/config/approved-exceptions.csv \
  -e M365_CERT_PASSWORD \
  -v "$PWD/config:/app/config:ro" \
  -v "$PWD/output:/app/output" \
  m365-forwarding-monitor:local
```

## Security Notes

- Store `config/certs` securely.
- Rotate the certificate at least annually.
- Remove old certificates from the app registration after rotation.
- Do not commit PFX, PEM, KEY, or password files.
- Keep output restricted to security/IT reviewers.
- This remains detection only: it does not approve, deny, block, delete, or modify forwarding.
