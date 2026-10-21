# Safe Email Send

A local, approval-gated SMTP queue and read-only IMAP observer. The worker is
ordinary Python: it does not call an LLM, depend on CoCo being open, or require
Snowball or Snowflake. The companion CoCo skill teaches an assistant how to use
the same CLI without bypassing approval.

Initial supported target: macOS and Gmail/Google Workspace with permitted app
password/IMAP access. Other platforms and providers are not integration-tested.

## Install

After cloning this repository to any location:

```sh
uv sync --locked
uv run --locked safe-email-send --help
uv run --locked pytest
```

For a standalone command available outside the checkout:

```sh
uv tool install /absolute/path/to/safe-email-send
safe-email-send --version
```

Use [setup](docs/setup.md) for identity, signature, environment variables and
Keychain configuration; [operations](docs/operations.md) for approvals, worker
controls, failure handling and reply observation. Start with a preview, not a send.

## CoCo integration

In CoCo Desktop, Agent Settings > Skills > Add Local Skill, select this repository's
`skills` directory. This registers the companion skill globally without copying
private configuration. Install the CLI first. An imported SKILL.md alone is not
the sender. The skill resolves `safe-email-send` on PATH and checks its version.

## Guarantees and limits

- Exact recipient and signed content approval; changes require a new approval.
- A shared mailbox queue, fixed spacing, rolling limits and global pause on one host.
- TLS certificate verification, explicit credential backend, no plaintext secret file.
- Uncertain submissions are held, never automatically resent.
- IMAP uses read-only selection and PEEK, with no mailbox modifications.
- No open tracking, recipient discovery, copy generation or automatic follow-ups.

Pacing cannot guarantee inbox placement or prevent restrictions. Recipient
expectations, complaints, address quality, corporate policy and domain authentication
still matter. SMTP acceptance is not delivery. This tool cannot account for all
other Gmail senders or coordinate multiple machines. Never use it to bypass
organizational controls. No real mail is sent by installation or tests.

The distributable code contains no user's identity, signature, credentials or
message history. Private state belongs outside the checkout. Do not publish those
files; inspect the distribution, not only `.gitignore`, before sharing.
