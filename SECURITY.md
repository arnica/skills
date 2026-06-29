# Security Policy

Thanks for helping keep **arnica/skills** and the people who install it safe.

This repository ships agent *skills* (prompt content) and plugin manifests that
run inside other people's coding agents. Because of that, the integrity of this
repo directly affects downstream users — please report problems privately rather
than opening a public issue or PR that could tip off attackers.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Preferred channels:

- **GitHub Private Vulnerability Reporting** — use the **"Report a vulnerability"**
  button under this repository's **Security** tab. This keeps the report private
  to the maintainers.
- **Email** — `security@arnica.io`. Encrypt if you can, and include enough detail
  to reproduce.

Please include:

- A clear description of the issue and its impact.
- Steps to reproduce (the affected file/skill, commands, or prompt sequence).
- Any logs, snippets, or proof-of-concept — with **secrets and tokens redacted**.

## Scope

In scope:

- Malicious, injectable, or unsafe instructions in any `SKILL.md`.
- Anything that could cause an installed agent to leak credentials, exfiltrate
  data, or run unintended commands.
- Tampering vectors (repo/release integrity) that could push untrusted content
  to users.
- Accidentally committed secrets.

Out of scope:

- The Arnica platform/API itself — report those through the Arnica product
  security process at `security@arnica.io`.

## Handling secrets

If you believe a token or other secret was committed here, **do not post it**.
Report it privately as above; the maintainers will rotate/revoke it. Never share
your own Arnica API token in a report.

## Our commitment

- We will acknowledge a valid report within a few business days.
- We will keep you updated on remediation and coordinate disclosure timing.
- We will credit reporters who want it once a fix is released.
