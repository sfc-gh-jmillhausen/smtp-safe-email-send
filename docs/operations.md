# Operations and recovery

All commands below target the configured mailbox's single local ledger. There is
no per-project state override. Work on only one machine per mailbox.

## Prepare, preview and approve

```sh
safe-email-send prepare /absolute/path/to/messages.json
safe-email-send preview BATCH_ID
```

Preview prints the complete signed text and HTML, recipient, subject, expiry,
eligibility and pacing policy. It does not load external links/images. Approval
must be for the exact digest and final content:

```sh
safe-email-send approve BATCH_ID --digest DIGEST --confirm APPROVE
```

These identifiers come from real preparation/preview output; do not type the
uppercase placeholders literally. The flag records workflow confirmation, not
proof that a human reviewed the content. CoCo must obtain user approval first.
Batch expiry defaults to 24 hours and cannot exceed seven days. Examples use
reserved domains and are only for offline previews, never real mail.

Multi-message batches require `scope: "campaign"` and this eligibility object:

```json
{
  "source": "Name of the reviewed eligibility source",
  "checked_at": "2026-01-05T09:00:00+00:00",
  "valid_until": "2026-01-06T09:00:00+00:00",
  "allowed_recipients": ["recipient@example.org"]
}
```

Use actual current timestamps. Eligibility must be checked within 24 hours and
expire within 24 hours of the check; it shortens batch expiry. This is supplied
evidence, not verification of consent by this program. Unknown JSON fields,
CC/BCC/attachments and duplicate source IDs/content are rejected.

## Start only when ready

```sh
safe-email-send resume --confirm RESUME
safe-email-send tick
safe-email-send send-now --confirm SEND
```

`resume` retrieves the configured credential but does not authenticate or send.
`tick` runs for at most ~50 seconds inside the send window, sending approved
messages one at a time over a single SMTP login, spaced by the configured
interval. `send-now` is the ad hoc version: it ignores the hours window and keeps
going until the approved queue is empty or the daily cap is hit. Both still
enforce approvals, spacing, daily caps, suppression and reply holds; `pause` works
between messages. A run may instead synchronize, hold or defer. IMAP failure
pauses all sending. No new credential test or email is implicitly authorized by installation.

For a background runner (macOS/Keychain only):

```sh
safe-email-send service-install --confirm INSTALL
safe-email-send service-start --confirm START
safe-email-send resume --confirm RESUME
```

Installation writes the LaunchAgent definition but does not load it and disables
the queue. Starting loads the service; only resume plus approved mail permits
sends. It runs a bounded tick once per minute inside the send window. It
does not wake a sleeping Mac or recover missed runs in a burst. The installed
interpreter must remain at its path; reinstall the definition after moving it.
No secret appears in the plist. The built-in launcher uses saved configuration,
not the calling terminal's environment overrides.

## Pause, cancel, suppress

```sh
safe-email-send status
safe-email-send pause
safe-email-send cancel BATCH_ID
safe-email-send suppress recipient@example.org --reason "Recipient opted out"
safe-email-send suppression-import /absolute/path/to/suppressions.json
safe-email-send service-stop --confirm STOP
```

Controls take the same nonblocking lock as a worker tick. If busy, retry when the
bounded tick finishes. A send already submitted cannot be recalled. Cancel affects
only unsent messages, never removes history. Suppression file format:
`{"source":"CRM opt-out export","recipients":["recipient@example.org"]}`.
This version has no unsuppress command; review suppression changes explicitly
instead of deleting the state database. Setup disables sending but preserves history.

## IMAP and events

```sh
safe-email-send sync
safe-email-send events --after 0
```

Events are printed locally (200 at a time, advance with `next_after`), not posted
to an app. A Snowball adapter is not included. The reader uses read-only mailbox
selection/PEEK and scans Inbox, advertised All Mail and Junk folders. No read flags,
labels or deletions change. Initial scans use tracked-send dates with a 30-day cap;
messages older than that baseline may not be observed. Each tick fetches at most
100 UID positions per selected folder, so large mailboxes may take multiple ticks.
An oversized initial result stops instead of silently truncating it.

Reply candidates use exact RFC references and participant checks. Sender headers
can be forged: these are observations, not verified identities. Any matched
response holds all queued mail to that person and blocks new approvals to them
until you read the reply and run
`safe-email-send release-response-hold person@example.org --confirm RELEASE`.
Held messages stay held; prepare fresh content if a follow-up is still right.
Auto-replies, delivery-status candidates and uncertain
matches are separate events. The reader does not infer all natural-language
unsubscribes; suppress them explicitly. No opens or complete spam-complaint feed.

## Errors and uncertain sends

`ACCEPTED` means Gmail accepted the message, not recipient inbox delivery.
Explicit SMTP rejections pause sending. Definitely pre-DATA connection failures
retry at most three attempts with increasing delays. An uncertain DATA outcome
or interrupted in-flight record becomes `UNKNOWN`, pauses the mailbox and blocks
resume. A confirmed acceptance followed by QUIT failure is still accepted.

Do not resend an UNKNOWN message or remove its database record. Inspect Sent by
its recorded Message-ID and reconcile with the provider/user. v0.1 deliberately
does not expose a force-retry or force-success command: unresolved ambiguity
requires review, not a guess. IMAP `SENT_OBSERVED` is evidence, not automatic
permission to retry. Editing content/source IDs to evade duplicate detection is
not reconciliation. Clock discontinuities/reboots require review then resume.

## Uninstall and retention

Stop the service and pause first. Remove only its own
`~/Library/LaunchAgents/local.safe-email-send.worker.plist` after unloading, then
uninstall the CLI via your installation method. Keep private state for audit and
duplicate protection. Explicitly decide when to remove local message history,
signature/config files and the `safe-email-send` Keychain item; uninstall does not
silently delete them. Never publish local state or private signatures with the code.