# Per-user setup

Prerequisites: Python 3.11+, uv, macOS for the service/Keychain, a Gmail/Workspace
mailbox whose organization permits app passwords and IMAP. Permission to create a
Google Cloud project is not required. Do not work around blocked IMAP policy.

1. Install using the root README. Create **your own** private HTML and plain-text
   signature fragments outside the checkout; each must contain your sender address.
   Examples are in `examples/`. Keep important contact details as text. Allowed
   HTML is intentionally limited; no scripts, forms or stylesheets. Only the
   signature file may contain static HTTPS logo images (no query string or
   credentials); message bodies cannot add images. The program never fetches them,
   and recipients may block logo loading.
2. Copy `.env.example` to a private location and edit its nonsecret values and
   absolute signature paths. The parser is literal `KEY=VALUE`: optional surrounding
   quotes, no interpolation, shell substitution or automatic dotenv discovery.
3. Run with the absolute path to that file:

   ```sh
   safe-email-send setup --env-file /absolute/path/to/private/mail.env
   safe-email-send status
   ```

   Setup persists only nonsecret configuration, disables sending, and never connects.
4. Revoke any credential exposed in chat. Generate a new Google app password only
   if organizational policy permits. Then run this **yourself**, not through chat:

   ```sh
   safe-email-send credential-set
   ```

   The hidden prompt saves directly to macOS Keychain. It does not authenticate or send.
5. Explicitly verify TLS/login and read-only mailbox access (no message fetch or send):

   ```sh
   safe-email-send doctor --connect
   ```

   SMTP success does not establish IMAP permission. Blocked/locked credentials stop
   operations; no credential or host fallback is attempted. Offline `doctor` checks
   configuration only and cannot prove authentication or deliverability.

## Configuration and environment variables

See `.env.example` for all variables. Precedence: defaults < saved nonsecret
configuration < explicit setup file < process `SAFE_EMAIL_*` environment overrides.
Unknown variables and invalid overrides fail closed. The app password is never
saved in JSON; a nonempty password in the explicit setup file is rejected.

Config: `~/.config/safe-email-send/config.json`. Queue/history:
`~/.local/share/safe-email-send/<mailbox-hash>/`. Paths derive from the user's home,
never the current repository. Changing working directories does not reset budgets.
Moving/deleting state can defeat protections; do not do that to clear a limit.
No distributed coordination: only one machine may send for a mailbox.

Timezone must be an explicit IANA name (for example `Europe/London`). Scheduled
sends run only inside `SEND_START_HOUR`-`SEND_END_HOUR` (default 08-17, weekdays
only unless `WEEKDAYS_ONLY=false`); `send-now` ignores the window. Defaults: 2
seconds between messages, up to 1000 messages/recipients per rolling 24 hours.
Ceilings: minimum 1 second, maximum 1000/day (Google Workspace allows about 2,000
per user per day). These keep sends from going out all at once; they are not a
Google-certified safe rate. The provider is fixed to Gmail, TLS and authenticated sender identity.

## Environment credentials (explicit alternative)

Set `SAFE_EMAIL_CREDENTIAL_BACKEND=env` and inject `SAFE_EMAIL_APP_PASSWORD` into
the worker's **process environment** using an approved secret injector. Never put
its value in a command argument, repository, sample file or LaunchAgent plist.
There is no fallback between `env` and `keychain`. Environment variables can be
visible to other same-user processes; Keychain is preferred on macOS.

LaunchAgents do not inherit arbitrary terminal exports. The built-in service
installer supports Keychain only; an environment-backed worker needs your own
approved launcher/injector. Missing injection stops, not a prompt/retry loop.

## Signature and configuration changes

The final signature is rendered before approval and its bytes/configuration are
fingerprinted. Editing identity, timezone, policy, credential backend or signature
invalidates pending approvals. Prepare a new batch and preview it. Password rotation
alone does not change message content. A signature in the message body is not an
acceptable substitute for the configured signature. Unknown existing signatures
cannot be detected perfectly: submit unsigned bodies and review the complete preview.

## Live readiness

Automated tests use fake accounts and blocked network access. They do not certify
your account's SMTP/IMAP permissions. Check corporate permission, recipient
expectations and SPF/DKIM/DMARC before sending. The software offers no spam-filter
bypass, warm-up scheme or inbox-placement guarantee.