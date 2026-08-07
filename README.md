# Arnica Security Skills

A plugin that bundles [Arnica](https://arnica.io) security skills for your
coding agent. Install it from the **Cursor Marketplace** or as a **Claude Code**
plugin and your agent gains a complete reference for the Arnica API plus an
opinionated, safety-gated workflow for triaging, fixing, and dismissing security
findings — all without leaving your editor.

## What's included

| Skill | What it does |
|---|---|
| **`arnica-api`** | Reference for the Arnica security API: endpoints, auth, query params, pagination, the error model, and the writable status enum. Loaded whenever the agent needs to call Arnica directly — query findings, manage products/assets/owners, scan SBOMs, review inventory, or integrate with the platform. |
| **`arnica-fix`** | A systematic, human-in-the-loop workflow for triaging code security findings (SAST, SCA, IaC, CI/CD, license, reputation — everything except secrets). Correlates findings to your source, classifies them as true/false positives, fixes the true positives, and dismisses the false positives via the API. Every side effect is gated behind explicit user approval. |

The two skills work together: `arnica-fix` defers to `arnica-api` for endpoint
reference, auth, pagination, and status semantics.

## Installation

### Cursor

**From the Marketplace: (Coming soon)**

1. Open **Cursor → Customize** (or browse [cursor.com/marketplace](https://cursor.com/marketplace)).
2. Search for **`arnica`** (or `arnica-security`).
3. Install the plugin. You can scope it to a single project or install it at the user level.

Once installed, the skills appear under **Agent Decides** and can also be
invoked manually in chat with `/arnica-api` or `/arnica-fix`.

**Local install (development / pre-publish):**

```bash
# Clone the repo
git clone https://github.com/arnica/skills.git

# Symlink (or copy) it into Cursor's local plugins folder
mkdir -p ~/.cursor/plugins/local
ln -s "$(pwd)/skills" ~/.cursor/plugins/local/arnica-security
```

Then restart Cursor or run **Developer: Reload Window**. The skills will show up
in the Plugins screen.

### Claude Code

Add this repository as a plugin marketplace, then install the plugin:

```text
/plugin marketplace add arnica/skills
/plugin install arnica-security@arnica
```

You can also manage it interactively via `/plugin` → **Browse marketplaces**.
After installing, the skills load automatically when relevant and can be invoked
explicitly by asking the agent to use `arnica-api` or `arnica-fix`.

## Prerequisites

Both skills talk to the Arnica API, so you need an API token.

1. Generate a token from the Arnica dashboard (**Admin → API**).
2. Store it locally — never commit it to a repository. The `printf` form below
   is paste-safe (`umask 077` + `chmod 600` make the file owner read/write only):

```bash
mkdir -p ~/.arnica
umask 077
printf 'TOKEN=%s\n' 'PASTE_YOUR_REAL_TOKEN_HERE' > ~/.arnica/.prod.env
chmod 600 ~/.arnica/.prod.env
```

> **zsh copy-paste note:** paste only the lines inside the code block and keep
> values quoted. Unquoted parentheses `()` in surrounding prose/comments make
> zsh emit `zsh: unknown sort specifier` (it treats `(...)` as a glob
> qualifier). Quoting — or prefixing a command with `noglob` — avoids it.

3. Grant the token the **least-privileged scopes** for your use case:

| Scope | Needed for |
|---|---|
| `risks:read` | Reading security findings |
| `risks:write` | Updating / dismissing finding status (required by `arnica-fix`) |
| `products:read` / `products:write` | Listing or managing products, assets, owners |
| `inventory:read` | Viewing repository inventory |
| `sbom-api:read` / `sbom-api:write` | SBOM scan status / uploads |
| `policies:read` | Viewing security policies |
| `status-checks:read` | Viewing CI/CD status checks |

> **Treat the token like a password.** Keep `~/.arnica/.prod.env` outside any git
> repository, don't paste it into chat/issues/screenshots, and rotate it
> immediately if it leaks.

## Usage

Just ask your agent in plain language — the relevant skill loads automatically:

- *"Triage the Arnica findings on this repo."* → runs the `arnica-fix` workflow.
- *"List all critical SAST findings for `my-org/my-repo`."* → uses `arnica-api`.
- *"Add this repository to the Payments product in Arnica."* → uses `arnica-api`.
- *"Dismiss the false-positive findings we just reviewed."* → `arnica-fix` Gate 2.

### How `arnica-fix` keeps you in control

The triage workflow processes findings in batches (by severity, then type) and
**never makes a change without your explicit approval**. There are three gates:

- **Gate 0 — branch scope:** confirm which branch's findings to triage.
- **Gate 1 — fix approval:** approve which true positives get fixed in code.
- **Gate 2 — dismiss/accept approval:** approve which findings get dismissed or risk-accepted via the API.

When in doubt, it errs on the side of leaving a finding open for human review
rather than dismissing a potentially real vulnerability.

## API reference at a glance

- **Base URL:** `https://api.app.arnica.io`
- **Auth:** `Authorization: Bearer <token>` (Arnica returns `403`, not `401`, for auth failures)
- **Docs:** [api.app.arnica.io/swagger](https://api.app.arnica.io/swagger)
- **Platform:** [app.arnica.io](https://app.arnica.io)

See the [`arnica-api`](skills/arnica-api/SKILL.md) skill for the full endpoint
reference, pagination semantics, and error model.

## Repository structure

```text
.
├── .cursor-plugin/
│   └── plugin.json           # Cursor plugin manifest
├── .claude-plugin/
│   ├── plugin.json           # Claude Code plugin manifest
│   └── marketplace.json      # Claude Code marketplace catalog
├── skills/
│   ├── arnica-api/
│   │   └── SKILL.md          # API reference skill
│   └── arnica-fix/
│       └── SKILL.md          # Finding-triage workflow skill
├── LICENSE
└── README.md
```

## Contributing

This plugin is open source so the community can inspect exactly what the skills
do before installing. Issues and pull requests are welcome at
[github.com/arnica/skills](https://github.com/arnica/skills).

## License

[MIT](LICENSE)
