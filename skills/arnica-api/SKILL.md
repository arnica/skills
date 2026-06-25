---
name: arnica-api
description: >-
  Reference for the Arnica security API: endpoints, auth, query params, error
  model, pagination, and the writable status enum. Use when calling Arnica
  endpoints directly, querying findings, managing products/assets/owners,
  scanning SBOMs, reviewing inventory, or integrating with the Arnica platform.
---

# Arnica API Skill

Reference for the Arnica API: endpoints, auth, query params, and the error
model. Use this skill any time you need to call the Arnica API directly.

> **Used by `arnica-fix`** — the triage workflow defers to this skill for
> endpoint reference, auth, pagination, and the writable status enum. If you're
> running an end-to-end finding triage, load `arnica-fix` and this skill
> together.

## Base Information

- **API Base URL**: `https://api.app.arnica.io`
- **API Documentation**: https://api.app.arnica.io/swagger
- **API Version**: 1.0
- **Authentication**: Bearer token

## Authentication Setup

### Required Token

Get your token from the Arnica dashboard, then expose it to your tooling. The
simplest option is an environment variable — **always quote the value**:

```bash
export ARNICA_API_TOKEN="your-token-here"
```

To call the API directly, pass it in the `Authorization` header as
`Authorization: Bearer <token>`.

> **Copy-paste note (zsh):** paste only the lines inside a code block, and keep
> tokens/values quoted. Unquoted parentheses `()` — common in the prose and
> comments around these snippets — make zsh emit
> `zsh: unknown sort specifier` because it treats `(...)` as a glob qualifier.
> Quoting (or prefixing a command with `noglob`) avoids this.

### Local token file
Store the token locally in a secure file and read it explicitly when needed.
The `printf` form below is paste-safe (no heredoc, no inline comments):

```bash
mkdir -p ~/.arnica
umask 077
printf 'TOKEN=%s\n' 'PASTE_YOUR_REAL_TOKEN_HERE' > ~/.arnica/.prod.env
chmod 600 ~/.arnica/.prod.env
```

`umask 077` and `chmod 600` ensure the file is owner read/write only (`0600`).

**Loading the token in scripts and ad-hoc commands** — use a targeted `grep`
instead of `source`-ing the file. This avoids leaking unrelated env vars and
works identically in `arnica-fix`:

```bash
TOKEN=$(grep '^TOKEN=' ~/.arnica/.prod.env | cut -d= -f2)
curl -sS -H "Authorization: Bearer $TOKEN" https://api.app.arnica.io/v1/auth/token
```

This keeps auth credentials separate from code and makes it easy to reuse the
token in scripts.

> **Never commit this file or the token.**
> - Keep `~/.arnica/.prod.env` outside any git repository. The `~/.arnica/` location above is intentional.
> - If you must store auth helpers inside a repo, add `.arnica/`, `*.env`, and `.prod.env` to `.gitignore` *before* writing the token.
> - Treat the token like a password: don't paste it into chat, issues, screenshots, or logs. Rotate it immediately if it leaks — Arnica dashboard, then API tokens, then revoke.
> - Prefer per-environment files such as `.prod.env` and `.staging.env`, each with the **least-privileged scopes** required. See "Required Scopes" below.

### Token Validation

Validate the token with `GET /v1/auth/token`:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" https://api.app.arnica.io/v1/auth/token
```

- `200` returns `{"arnicaOrgId": "...", "keyId": "..."}` — the token is valid.
- `403` means the token is invalid, expired, or revoked. Arnica returns `403`, not `401`, for auth failures.

## Core API Operations

### 1. Risk Management

#### Get Risk Findings
```bash
# List all findings
GET /v1/risks/findings

# Get specific finding
GET /v1/risks/findings/{id}

# Query: type (SAST, SCA, IAC, LICENSE, REPUTATION, SECRET) — uppercase
# Query: severity (critical, high, medium, low, info, unknown) — lowercase, exact match
# Query: status — see full enum below; common: requires_review, in_progress,
#                 risk_accepted, resolved, resolved_automatically,
#                 dismiss_not_accurate, dismiss_no_capacity, dismiss_risk_is_tolerable
# See "Finding Triage & Review Workflow" below for full filter semantics.
```

#### Permission Risks (GitHub/Azure)
```bash
# GitHub permission risks
GET /v1/risks/permissions/github/{githubPermissionRiskType}
# githubPermissionRiskType: owner | admin | maintain | write | codeowners

# Azure permission risks
GET /v1/risks/permissions/azure/{azurePermissionRiskType}
# azurePermissionRiskType: admin | codecontributor | pullrequestcontributor
```

> Returns `404 {"message":"Report not found"}` when the report has not been generated for the org yet (the path/type is still valid).

#### Hardening Recommendations
```bash
# GitHub stale users
GET /v1/risks/hardening/github/stale/users

# Azure stale users
GET /v1/risks/hardening/azure/stale/users

# Stale repositories
GET /v1/risks/hardening/github/stale/repositories
GET /v1/risks/hardening/azure/stale/repositories
```

#### Update Finding Status
```bash
PUT /v1/risks/{id}/status
Content-Type: application/json

{
  "status": "risk_accepted",
  "reason": "Updated via API"
}

# Body fields (FindingUpdateDto):
#   status (required) — one of the writable statuses below
#   reason (required) — free-text rationale (min length 1)
#
# Writable statuses (from FindingUpdateDto.enum — narrower than the read enum):
#   resolved, in_progress, requires_review, pending_review, risk_accepted,
#   dismiss_no_capacity, dismiss_not_accurate, dismiss_risk_is_tolerable,
#   dismiss_secret_not_used
#
# DO NOT send these (read-only / system-managed):
#   resolved_automatically, dismissed_automatically, awaiting_user_input,
#   mitigation_in_progress, mitigation_pending_pr, mitigation_failed,
#   dismiss_no_option_chosen_yet
#
# Path note: {id} is the OpenAPI placeholder name `{sortKey}`, but the value
# you put there is the finding `id` from the listing response (the top-level
# `sortKey` field is always `null` — ignore it). The id contains `/`, `:`,
# `@`, etc. and MUST be URL-encoded.
#
# Rollback: to undo a wrong dismissal, PUT `requires_review` (it's in the
# write enum) — this returns the finding to the triage queue.

# Example:
#   ID='01bc4...0510/js/package-lock.json:remove-strict-webpack-plugin@0.1.2'
#   ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ID")
#   curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
#     -d '{"status":"resolved","reason":"verified false positive"}' \
#     "https://api.app.arnica.io/v1/risks/$ENC/status"
# Successful update returns HTTP 204 (no body).
```

### 2. Products Management

#### List Products
```bash
GET /v1/products

# Query parameters (verified against the live OpenAPI spec):
# - offset: pagination offset (default 0, max 999999)
# - limit:  items per page (default 100, max 200)
# - name:   filter by product name (substring match)
# - management: filter by ManagementType (automatic | manual)
```

> Returns `{"items": [...]}` (a wrapped object). Pagination uses `offset`/`limit`, **not** `skip`/`take`/`sort`. (Unknown query params are silently ignored, so misspelled params return the default first 100 items.)
>
> **Heads-up on pagination naming**: `/v1/products` uses `offset`/`limit`, while `/v1/risks/findings` uses `page`/`limit`. Both happen to use `limit`, but the offsetting parameter differs.

#### Get Product Details
```bash
GET /v1/products/{productId}
```

#### Create Product
```bash
POST /v1/products
Content-Type: application/json

{
  "name": "My Security Product"
}
```

> The `ProductCreate` body accepts **only** `name` (1–50 chars). Sending `description`, `businessImportance`, etc. returns `400 "property X should not exist"`. Newly created products default to `management: "manual"` with empty `assets`/`owners`/`champions`. Returns `409` if the name already exists.

#### Update Product
```bash
PATCH /v1/products/{productId}
Content-Type: application/json

{
  "name": "Updated Name"
}
```

> The `ProductUpdate` body accepts **only** `name`. For everything else, use the dedicated sub-resource endpoints:
> - Assets → `POST /v1/products/{productId}/assets`
> - Owners → `POST /v1/products/{productId}/owners` (see "Owners & Champions" below)
> - Security champions → `POST /v1/products/{productId}/champions`

#### Delete Product
```bash
DELETE /v1/products/{productId}
```

### 3. Assets Management

#### Add Asset (Repository or Location) to a Product
```bash
POST /v1/products/{productId}/assets
Content-Type: application/json

{
  "url": "https://github.com/my-org/my-repo"
}
```

> The `AssetAdd` body accepts **only** `url` (1–2000 chars). Sending `type`, `scmType`, or `integrationId` returns `400 "property X should not exist"`. Arnica derives the SCM/integration from the URL itself.
>
> Supported URL examples (from the live OpenAPI examples):
> - GitHub repo: `https://github.com/my-org/my-repo`
> - GitHub org/location: `https://github.com/my-org`
> - Azure DevOps repo: `https://dev.azure.com/MyOrg/MyProj/_git/MyRepo`
> - Azure DevOps org: `https://dev.azure.com/MyOrg`
> - BitBucket Server: `http://my.bitbucket.deployment.net/projects/PROJ/repos/my-repo/browse`
> - BitBucket Cloud: `https://bitbucket.org/my-workspace/my-repo`
> - GitLab repo: `https://gitlab.com/my-group/my-repo`
> - GitLab group: `https://gitlab.com/groups/my-group`
>
> Responses: `201 Created`, `400 Invalid request`, `403 Forbidden (needs products:write)`, `404 Repo/Location/Product not found`, `409 Product already includes this asset`.

#### Update Repository Asset
```bash
PATCH /v1/products/{productId}/assets/repositories/{repositoryId}
Content-Type: application/json

{
  "slaBranches": ["main", "release/*"],
  "pathPrefixes": ["src/"]
}
```

> The `RepositoryAssetUpdate` body accepts only `slaBranches` (string[]) and `pathPrefixes` (string[]). At least one of the two must be specified; each list is bounded 0–100 items. There is no `customRiskScore` field — that example was incorrect in earlier revisions.

#### Delete Asset
```bash
DELETE /v1/products/{productId}/assets/repositories/{repositoryId}
DELETE /v1/products/{productId}/assets/locations/{locationId}
```

### 4. Owners & Champions

Owners and security champions are managed via dedicated endpoints — **not** through `PATCH /v1/products/{productId}` (which only accepts `name`). Both resolve a user by SCM identity and return an Arnica `identity` id you'll use for subsequent updates/deletes.

#### Add Product Owner
```bash
POST /v1/products/{productId}/owners
Content-Type: application/json

{
  "scmType": "github",
  "displayName": "Jane Doe"
}
```

> **Body shape (`ProductOwnerAdd`)**: `scmType` is **required** (one of `github | azure-devops | bitbucket-server | bitbucket-cloud | gitlab`). You must also provide **at least one** of `scmId`, `username`, `email`, `displayName` to identify the user. Optional: `integrationId` (needed to disambiguate when multiple on-prem integrations share usernames) and `comment` (free-text note).
>
> Responses: `201 Created` returning `{ id, primaryDisplayName, primaryEmail, comment? }` — keep `id` (the identity id) for later PATCH/DELETE. `400` invalid body, `403` missing `products:write`, `404` product or user not found / search criteria ambiguous, `409` user is already an owner of this product.
>
> Example:
> ```bash
> curl -X POST -H "Authorization: Bearer $ARNICA_API_TOKEN" \
>   -H 'Content-Type: application/json' \
>   -d '{"scmType":"github","displayName":"Jane Doe"}' \
>   "https://api.app.arnica.io/v1/products/$PRODUCT_ID/owners"
> ```

#### Update Product Owner
```bash
PATCH /v1/products/{productId}/owners/{identityId}
Content-Type: application/json

{
  "comment": "Primary on-call for this product"
}
```

> The `ProductOwnerUpdate` body accepts **only** `comment`. To "change" the owner identity, delete and re-add. Returns `200` with the updated `ProductOwner`.

#### Delete Product Owner
```bash
DELETE /v1/products/{productId}/owners/{identityId}
# 204 No Content on success
```

#### Add Security Champion
```bash
POST /v1/products/{productId}/champions
Content-Type: application/json

{
  "scmType": "github",
  "username": "githubuser"
}
```

> **Body shape (`SecurityChampionAdd`)**: same identity-resolution contract as `ProductOwnerAdd` — `scmType` required, plus at least one of `scmId | username | email | displayName`, optional `integrationId`. **No `comment` field** (champions don't support comments). Returns `201` with `{ id, primaryDisplayName, primaryEmail, reason }` where `reason` is the `AssignmentReason` (e.g. `codeAuthor`). `409` if already a champion.

#### Delete Security Champion
```bash
DELETE /v1/products/{productId}/champions/{identityId}
# 204 No Content on success
```

> Champions have **no PATCH** endpoint — to modify, delete and re-add.

### 5. SBOM Scanning (Enterprise)

#### Start SBOM Scan
```bash
POST /v1/sbom/scan/upload
Content-Type: multipart/form-data

File: [sbom.json or sbom.xml]
```

#### Check Scan Status
```bash
GET /v1/sbom/scan/{scanId}/status
```

### 6. Inventory

#### List Repositories
```bash
GET /v1/inventory/repos

# Returns all connected repositories
# Requires scope: inventory:read
```

### 7. Security Policies

#### List Policies
```bash
GET /v1/policies
```

> Returns an object keyed by sub-type (currently `global`, `code_risk`, `secrets`). Each value is the full policy doc (rules, conditions, config).

#### Get Policy by Sub-Type
```bash
GET /v1/policies/{subType}

# subType (PolicySubType enum): code_risk | secrets
# Plus the implicit "global" key from /v1/policies.
# (SAST/SCA/IaC/Secrets/License/Reputation are *finding types*, not policy sub-types — passing them returns 404.)
```

### 8. Status Checks

#### Find Status Check
```bash
POST /v1/status-checks/find
Content-Type: application/json

{
  "integrationType": "github",
  "integrationOrgId": "my-org",
  "repoId": "my-repo",
  "sha": "abc123def456...",
  "branch": "feature/foo",
  "targetBranch": "main"
}
```

> The `StatusCheckFindDto` body requires **all** of: `integrationType` (one of `github | azure-devops | bitbucket-server | bitbucket-cloud | gitlab`), `integrationOrgId`, `repoId`, `sha` (commit SHA of the latest PR/MR commit), `branch` (source), `targetBranch` (where you're merging to). Optional: `projectId` (not supported when `integrationType: "github"`). The earlier `{repository, branch}` example was incorrect.
>
> `integrationOrgId` semantics by SCM:
> - GitHub → organization name
> - Azure DevOps → organization ID
> - BitBucket → workspace ID
> - GitLab → group ID

#### Get Status Check
```bash
GET /v1/status-checks/{id}
```

## Common Workflows

### Workflow 1: Analyze Security Findings
```
1. GET /v1/risks/findings
2. Filter by severity and type
3. GET /v1/risks/findings/{id} (detailed info)
4. PUT /v1/risks/{id}/status (update status — OpenAPI calls the path param {sortKey}, but use the finding's `id` field)
```

### Workflow 2: Create and Manage Product
```
1. POST /v1/products (create product)
2. POST /v1/products/{productId}/assets (add assets — repositories or org/group/workspace locations)
3. GET /v1/products/{productId} (verify setup)
4. Monitor findings via /v1/risks/findings (use ?product={productId} to scope)
```

### Workflow 3: Permission Risk Assessment
```
1. GET /v1/risks/permissions/github/{type}
2. GET /v1/risks/hardening/github/stale/users
3. Identify excessive permissions
4. Recommend remediation
```

### Workflow 4: Repository Inventory Check
```
1. GET /v1/inventory/repos
2. Compare with managed products
3. Add missing repos via POST /v1/products/{id}/assets
4. Update product coverage
```

## Finding Triage & Review Workflow

### Asset-based findings queries
Use repository and branch scoping when fetching findings for a specific codebase. The API accepts an `asset` query parameter in the form:

```
{scm}:{organization}/{project}/{repo}#{branch}
```

For GitHub, where there is no project segment, use an empty project field:

```
github:my-org//my-repo#main
```

For SCMs with a required project segment:

```
azure-devops:my-org/my-project/my-repo#main
```

> **Always URL-encode the asset string before placing it in the query
> parameter.** The value contains `:`, `/`, and especially `#` — and `#` is a
> URL fragment delimiter, so an unencoded `#main` is silently stripped before
> the request even leaves your machine (and shells eat it as a comment if
> unquoted). Encode like this:
>
> ```bash
> ASSET="github:my-org//my-repo#main"
> ASSET_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ASSET")
> curl -H "Authorization: Bearer $TOKEN" \
>   "https://api.app.arnica.io/v1/risks/findings?asset=${ASSET_ENC}&limit=20"
> ```

### Common SCM formats
- `github:org//repo#branch`
- `gitlab:group/subgroup/repo#branch` or `gitlab:group//repo#branch`
- `azure-devops:org/project/repo#branch`
- `bitbucket-cloud:workspace/project-key/repo#branch`
- `bitbucket-server:https%3A%2F%2Fserver.fqdn.com/PROJ/repo#branch` *(verify per tenant — see note below)*

> **Bitbucket-Server caveat**: the `bitbucket-server:` form embeds a URL-encoded base URL as the "organization" segment (`https%3A%2F%2F…`). This pattern is not part of the OpenAPI spec and varies by tenant deployment. Before relying on it, confirm the exact format for your org by inspecting the `asset` field of an existing finding from a Bitbucket-Server repo:
>
> ```bash
> # Find one BBS-backed finding and read its asset shape
> curl -sS -H "Authorization: Bearer $ARNICA_API_TOKEN" \
>   "https://api.app.arnica.io/v1/risks/findings?limit=100" \
> | jq '.[] | select(.asset.scm == "bitbucket-server") | .asset' | head -20
> ```
>
> Then build the `asset=` query string from those exact `scm`/`orgId`/`project`/`repo`/`branch` values.

### Deriving the asset string from a git repo

When you're working from a local checkout, derive the `asset=` query parameter
from `git remote get-url origin`. The `arnica-fix` skill uses this end-to-end
for triage workflows; the recipe is reusable any time you want to scope findings
to "the repo I'm currently in".

**1. Get remote URL and current/default branch:**

```bash
REMOTE_URL=$(git remote get-url origin)
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null \
  | sed 's|refs/remotes/origin/||')
# Fallback if origin/HEAD isn't set:
#   git rev-parse --verify origin/main   || git rev-parse --verify origin/master
```

**2. Detect SCM type** from the host portion of the URL:

| Host pattern | SCM type |
|---|---|
| `github.com` | `github` |
| `dev.azure.com` or `*.visualstudio.com` | `azure-devops` |
| `gitlab.com` | `gitlab` |
| `bitbucket.org` | `bitbucket-cloud` |
| Self-hosted Bitbucket / Stash | `bitbucket-server` |
| Self-hosted GitLab | `gitlab` |

For ambiguous self-hosted hosts (could be GitLab, Bitbucket Server, GitHub
Enterprise, …), build candidate asset strings for **every plausible SCM type**
and try each — the first one that returns non-empty results is the correct one.
Only fall back to asking the user when all candidates return zero.

**3. Extract `org` / `project` / `repo`** — rules differ per SCM:

**GitHub** (`github.com/{org}/{repo}.git`, no project segment):
```bash
ORG=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|')
REPO=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/][^/]+/([^/.]+)(\.git)?$|\1|')
PROJECT=""
```

**Azure DevOps** (`dev.azure.com/{org}/{project}/_git/{repo}`):
```bash
ORG=$(echo "$REMOTE_URL"     | sed -E 's|.*dev\.azure\.com/([^/]+)/.*|\1|')
PROJECT=$(echo "$REMOTE_URL" | sed -E 's|.*dev\.azure\.com/[^/]+/([^/]+)/_git/.*|\1|')
REPO=$(echo "$REMOTE_URL"    | sed -E 's|.*/_git/([^/.]+)(\.git)?$|\1|')
```

**GitLab** (`gitlab.com/{group}[/{subgroup}…]/{repo}.git`):
```bash
PATH_PART=$(echo "$REMOTE_URL" | sed -E 's|.*gitlab\.com[:/](.+?)(\.git)?$|\1|')
ORG=$(echo "$PATH_PART" | cut -d/ -f1)
REPO=$(echo "$PATH_PART" | rev | cut -d/ -f1 | rev)
PROJECT=$(echo "$PATH_PART" | sed -E "s|^$ORG/||; s|/$REPO$||")  # may be empty
```

**Bitbucket Cloud** (`bitbucket.org/{workspace}/{repo}.git`): you typically
also need the project key from the Bitbucket UI — it isn't in the clone URL.
**Bitbucket Server**: `org` is the URL-encoded server base URL (see caveat
above); `project` is the `PROJ` segment; `repo` is the repo slug.

**4. Assemble** — always exactly 3 path segments (use empty string for missing
project, producing `//`):

```bash
ASSET="${SCM_TYPE}:${ORG}/${PROJECT}/${REPO}#${BRANCH}"
```

Worked examples:

| SCM | Asset string |
|---|---|
| GitHub | `github:my-org//my-repo#main` |
| Azure DevOps | `azure-devops:Pasture/Goats/GitGoat#main` |
| GitLab (top-level group) | `gitlab:my-group//my-repo#main` |
| GitLab (with subgroup) | `gitlab:my-group/my-subgroup/my-repo#main` |
| Bitbucket Cloud | `bitbucket-cloud:workspace/project-key/my-repo#main` |
| Bitbucket Server | `bitbucket-server:https%3A%2F%2Fserver.fqdn.com/PROJ/my-repo#main` |

### Finding filters
Use exact match filters when querying findings. Full query-parameter list (from the live OpenAPI schema for `GET /v1/risks/findings`):

- `severity=critical|high|medium|low|info|unknown` (exact match — `info` is informational, `unknown` is the scanner's "couldn't determine"; both are typically excluded from triage workflows)
- `type=SAST|SCA|IAC|LICENSE|REPUTATION|SECRET` (uppercase)
- `status=<FindingStatuses>` — see "Safe status updates" below for the full enum; use `requires_review` to focus on actionable issues
- `asset=<asset-string>` to scope to a specific repo/branch
- `product=<productId>` to scope to all assets of a product
- `sla=<bool>` to filter by SLA breach
- `secretType=...` and `secretValidation=...` for secret-finding refinement
- `expand=true` for full details (caps page size at 20)
- `page` / `limit` for pagination

Combine repeated parameters for multiple values:

```
severity=critical&severity=high&type=SAST&type=SCA
```

### Expand and pagination

`limit` defaults to **20** and is capped at **100** server-side (values above 100 are silently clamped, not rejected). `page` defaults to **1**.

When `expand=true`, the page size is further capped at **20** regardless of what you send for `limit`.

Always page through results until the returned page is shorter than the requested limit (i.e. `len(page) < limit` ⇒ last page). Don't rely on a total/count in the response — there isn't one.

Examples:

```
# Bulk listing (use limit=100 to minimize round-trips)
GET /v1/risks/findings?status=requires_review&limit=100&page=1

# Detailed listing (expand caps page size at 20)
# NOTE: the asset value MUST be URL-encoded — see the asset-encoding callout above.
# Encoded form of asset=github:my-org//my-repo#main:
GET /v1/risks/findings?asset=github%3Amy-org%2F%2Fmy-repo%23main&severity=high&status=requires_review&expand=true&limit=20&page=1
```

### Response format
The findings endpoint returns a flat JSON array of finding objects, not a wrapped `data` object.

The `asset` object on each finding has this shape (verified against live responses):

```json
{
  "scm": "github",
  "url": "https://github.com",
  "orgId": "my-org",
  "project": null,
  "repo": "my-repo",
  "branch": "main",
  "path": "path/to/file.py",
  "link": "https://github.com/my-org/my-repo/blob/main/path/to/file.py#L25"
}
```

Use `asset.path`, `asset.repo`, and `asset.branch` to correlate findings to source code, and `asset.link` for a direct deep link.

When `expand=true`, findings may include a `details` object with fields such as:
- `description`
- `code`
- `ruleId`
- `references`
- `package`, `packageType`, `version`
- `recommendation`

### Safe status updates
Use the findings status endpoint carefully:

```
PUT /v1/risks/{id}/status
Content-Type: application/json
{
  "status": "dismiss_not_accurate",
  "reason": "False positive after triage"
}
```

> The `{id}` path segment is the finding `id` from `GET /v1/risks/findings`
> (the OpenAPI calls it `{sortKey}` but the top-level `sortKey` field on
> responses is always `null` — use the `id` field). The id contains `/`, `:`,
> `@` and must be **URL-encoded** before being placed in the path. A successful
> update returns **HTTP 204** with no body.
>
> **Rollback**: to undo a wrong dismissal or risk-acceptance, PUT
> `requires_review` (it's in the write enum below). The finding goes back to
> the triage queue.

Two related enums exist:

**`FindingStatuses`** (read enum — what you may see on a finding):
`requires_review`, `pending_review`, `in_progress`, `awaiting_user_input`,
`risk_accepted`, `resolved`, `resolved_automatically`,
`dismissed_automatically`, `dismiss_no_capacity`, `dismiss_not_accurate`,
`dismiss_risk_is_tolerable`, `dismiss_secret_not_used`,
`dismiss_no_option_chosen_yet`, `mitigation_in_progress`,
`mitigation_pending_pr`, `mitigation_failed`.

**`FindingUpdateDto.status`** (write enum — what you may send to `PUT /v1/risks/{id}/status`):
- `resolved`
- `in_progress`
- `requires_review`
- `pending_review`
- `risk_accepted`
- `dismiss_no_capacity`
- `dismiss_not_accurate`
- `dismiss_risk_is_tolerable`
- `dismiss_secret_not_used`

Anything in the read enum but not the write enum is system-managed and cannot be set via the API (e.g. `*_automatically`, `awaiting_user_input`, `mitigation_*`, `dismiss_no_option_chosen_yet`).

### Approval / triage guidance
For code-review and triage workflows, always verify findings before changing status.
When triaging:
- classify findings by severity and type
- review source correlation and `details`
- only dismiss or accept risk with high confidence
- preserve findings for human review if uncertain

## Required Scopes

- `risks:read` - Read security findings
- `risks:write` - Update finding status
- `products:read` - List/view products
- `products:write` - Create/update/delete products
- `inventory:read` - View repository inventory
- `sbom-api:read` - Check SBOM scan status
- `sbom-api:write` - Upload SBOM scans
- `policies:read` - View security policies
- `status-checks:read` - View CI/CD status checks

## Error Handling

Common HTTP Status Codes:
- `200` - Success
- `201` - Created
- `204` - No Content (e.g. successful PUT/DELETE)
- `400` - Bad Request (invalid parameters or body validation; also returned for malformed path params, e.g. a `productId` that isn't a valid UUIDv4)
- `403` - Forbidden — **Arnica returns `403` for both invalid/expired tokens and for tokens missing the required scope.** Treat `403` as "auth or scope problem"; the response body's `message` will distinguish (e.g. `"Forbidden"` vs. `"…required scopes [products:write]"`).
- `404` - Not Found (resource missing, or a report has not been generated yet — see permission-risk endpoints)
- `409` - Conflict (e.g. duplicate product name, asset already attached)
- `429` - Rate Limited (back off and retry)
- `500` - Server Error

Error body shape (typical):

```json
{
  "ui": true,
  "message": "human-readable message",
  "error": "Forbidden | Bad Request | Not Found | …",
  "statusCode": 403,
  "id": "errid_…"
}
```

The `id` field (e.g. `errid_80be5d1f-…`) is a server-side correlation id you can quote when reporting issues to Arnica support.

> Note: Arnica does **not** appear to use HTTP `401` for invalid bearer tokens — it returns `403 Forbidden`. Don't write code that branches specifically on `401`.

## Tips & Best Practices

1. **Token Management**: Use environment variables, never commit tokens
2. **Rate Limiting**: On `429` responses, back off with exponential delay + jitter (suggested: start at 1s, double on each retry, max 30s, cap at 5 retries). When fanning out parallel requests (e.g. paginated `expand=true` listings), keep concurrency bounded — 5 in-flight requests is a safe default.
3. **Pagination**: Use `offset`/`limit` for `/v1/products` and `page`/`limit` for `/v1/risks/findings` (each endpoint's parameters are listed in its section above). Always paginate until a page is shorter than the requested limit.
4. **Filtering**: Filter on API side when possible, not in application
5. **Scopes**: Request minimal required scopes for security
6. **Error Responses**: Check response body for detailed error messages
7. **Testing**: Start with GET requests to validate token and connectivity
8. **URL-encode dynamic path/query values**: Asset strings, finding IDs, and any other value containing `:`, `/`, `#`, `@` must be URL-encoded before being interpolated into a URL. See the asset-encoding callout under "Asset-based findings queries".

## Example: Get All Findings and Group by Severity

```python
import requests
import os

API_TOKEN = os.getenv("ARNICA_API_TOKEN")
BASE_URL = "https://api.app.arnica.io"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# Get all findings (note: response is a flat JSON array, not a wrapped object)
response = requests.get(
    f"{BASE_URL}/v1/risks/findings",
    headers=headers,
    params={"status": "requires_review", "limit": 20, "page": 1},
)
response.raise_for_status()
findings = response.json()  # list[dict]

# Group by severity (API returns lowercase severities)
by_severity = {}
for finding in findings:
    severity = finding.get("severity", "unknown")
    by_severity.setdefault(severity, []).append(finding)

# Print summary
for severity in ["critical", "high", "medium", "low"]:
    count = len(by_severity.get(severity, []))
    print(f"{severity}: {count} findings")
```

## Resources

- [Arnica Swagger Documentation](https://api.app.arnica.io/swagger)
- [Arnica Security Platform](https://app.arnica.io)
- API Scopes Documentation: See scope definitions for each endpoint
