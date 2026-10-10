---
name: arnica-api
description: >-
  Reference for the Arnica security API: endpoints, auth, query params, error
  model, pagination, and the writable status enum. Use when calling Arnica
  endpoints directly, querying or reporting on findings (SLA, severity,
  per-product), reading product risk totals from the dashboard, applying
  dismissals or severity overrides decided by an external process, tuning a
  product's AI SAST prompt, managing
  products/assets/owners, scanning SBOMs, reviewing inventory, or integrating
  with the Arnica platform.
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
- **Authentication**: Bearer token (OpenAPI `bearerFormat`: `arnica_{token}`)

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
TOKEN=$(sed -n 's/^TOKEN=//p' ~/.arnica/.prod.env)
curl -sS -H "Authorization: Bearer $TOKEN" https://api.app.arnica.io/v1/auth/token
```

> **Do not use `cut -d= -f2` to extract the token.** Arnica tokens are
> base64-encoded and frequently end in `=` or `==` padding; `cut -d= -f2` splits
> on `=` and keeps only the second field, silently dropping the padding. That
> yields a truncated token that Arnica rejects with a generic `403 Forbidden` —
> the same response as an invalid/expired key, so the failure looks like an auth
> problem rather than a parsing bug. `sed -n 's/^TOKEN=//p'` strips only the
> leading `TOKEN=` prefix and preserves the rest of the line verbatim.

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
# Query: sla=true|false — finding HAS an SLA (slaStart set), NOT "SLA breached"
# Query: product=<productId> — scope to one product
# See "Finding filters" below for full semantics, and "Findings Query Playbook"
# before pulling findings for a report.
```

> Sorted by `lastUpdated` **descending**. Findings updated while you page can
> shift between pages, so long pulls may see a duplicate or miss an item —
> de-duplicate by `id`.

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
#   dismiss_secret_not_used, snooze
#   (snooze: the body has no unsnooze-date field; the finding's `unsnoozeDate`
#   and `snoozeReason` are read-only on responses. Confirm behavior before
#   using it in automation.)
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

#### Override Finding Severity
```bash
PUT /v1/risks/{id}/severity
Content-Type: application/json

{
  "severity": "low",
  "reasonCategory": "compensating_control",
  "note": "Only reachable from an internal admin tool"
}

# FindingSeverityUpdateDto:
#   severity (required)       critical | high | medium | low | info
#   reasonCategory (required) business_asset_context | compensating_control |
#                             org_risk_policy | other
#   note (optional, max 2000 chars; the UI requires one, so send one)
# 204 on success. Re-overriding replaces the previous override; every change
# is recorded in the finding's history.
# 400 for SCA findings (their severity comes from the advisory; use the
#     per-CVE override below), 403 if manual severity override is not enabled
#     for the org, 404 if the finding doesn't exist.

# Reset to the scanner-calculated severity
DELETE /v1/risks/{id}/severity
{ "reason": "Override no longer needed" }      # reason required, 1–2000 chars
```

#### Override a CVE's Severity (SCA)
```bash
PUT /v1/risks/{id}/cves/{cveId}/severity
{ "severity": "low", "reasonCategory": "reachability", "note": "..." }
# reasonCategory: same as above PLUS reachability | epss (CVE-level only)

DELETE /v1/risks/{id}/cves/{cveId}/severity
{ "reason": "..." }
```

> Same `{id}` rules as the status endpoint: use the finding `id`, URL-encoded.
> All require `risks:write`. For applying decisions in bulk, see "Acting on
> Findings".

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

# Query parameters:
# - offset: default 0, max 999999
# - limit:  default 100, max 200
# - integrationOrgId: only repos in this SCM org
# - topic: only repos with this topic (max 100 chars)
# Requires scope: inventory:read
```

> Returns `{"items": [...]}`. Each item has `repositoryId` (Arnica's UUID — use
> it for path exclusions), `repoId` (the SCM's own id), `name`, `fullName`,
> `integrationType`, `integrationOrgId`, `organizationName`, `baseUrl`,
> `webUrl`, `defaultBranch`, `visibility`.

#### Repository Path Exclusions
```bash
GET /v1/inventory/repos/{repositoryId}/settings/path-exclusions   # inventory:read
PUT /v1/inventory/repos/{repositoryId}/settings/path-exclusions   # inventory:write
Content-Type: application/json

{ "patterns": ["^docs/", "vendor/", "\\.generated\\."] }
```

> **PUT replaces the whole list** (max 10 regex patterns). To add one, GET the
> current list, append, and PUT the combined array; `[]` clears all. Side
> effects: open findings matching a pattern are auto-resolved, findings
> auto-resolved by a removed pattern reopen, and a rescan is triggered.
> Confirm with the user before calling PUT.

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

### 9. Audit Events

Read-only audit log of actions taken in your Arnica org (who did what, when, and
through which interface). Useful for SIEM ingestion, compliance exports, and
answering "who changed this policy / product / integration".

#### List Audit Events
```bash
GET /v1/audit-events

# Query parameters (from the live OpenAPI schema):
# - limit:     items per page (default 50, min 1, max 100)
# - offset:    number of matching events to skip (default 0, max 999999)
# - startDate: inclusive lower timestamp boundary, ISO 8601 date or datetime
#              (e.g. 2026-08-03T00:00:00Z or 2026-08-03)
# - endDate:   inclusive upper timestamp boundary, ISO 8601 date or datetime
#              (e.g. 2026-08-03T23:59:59.999Z)
# - userId:    actor EMAIL address to match (repeat to match any of several)
# - eventType: event DOMAIN to match (repeat to match any of several) — one of
#              AUTHENTICATION | AUTHORIZATION | POLICY | PRODUCT | INTEGRATION |
#              API | AI | INVENTORY
# - eventAction: action to match (repeat to match any) — one of
#              CREATE | READ | UPDATE | DELETE | LOGIN | LOGOUT
# - sortBy:    only "timestamp" (the default) is supported
# - sortDesc:  newest first when true (default true)
#
# Requires scope: audit:read
```

> Returns a **wrapped** object `{ "items": [...], "total": <number> }`, where
> `total` is the count of all events matching the filters *before* pagination —
> so unlike `/v1/risks/findings`, you can paginate against a known total.
>
> **Pagination naming**: audit-events uses `offset`/`limit` (like `/v1/products`),
> **not** `page`/`limit` (which `/v1/risks/findings` uses).
>
> **Repeatable filters**: repeat `userId`, `eventType`, or `eventAction` to match
> *any* of the supplied values (OR semantics). Date boundaries are inclusive.
>
> **Auth note (differs from the rest of the API)**: a *missing* API key returns
> `401`, while an *invalid* key or one missing the `audit:read` scope returns
> `403`. Everywhere else Arnica collapses both into `403` — audit-events is the
> exception that actually emits `401`. Distinguish invalid-key from
> missing-scope by the response body's `message`: missing scope returns
> `"Missing required scope(s): [audit:read]"`, invalid key returns a plain
> `"Forbidden"`.
>
> **Self-referential logging (footgun)**: every call to `GET /v1/audit-events`
> writes itself into the audit log as
> `{ eventAction: "READ", eventDomain: "AUTHORIZATION", resourceType: "AuditEventList", resourceName: "Audit Events", newValue: { eventCount: <n> } }`,
> where `eventCount` is the number of items the caller received (0 on an empty
> page). Consequences:
> - A polling job will fill the log with its own reads. Poll infrequently, and
>   attribute reads to a dedicated API key (`apiTokenName`) so you can identify
>   and post-filter them.
> - "Show me recent activity" queries will surface the querier's own calls at
>   the top. Either post-filter client-side (drop items where
>   `resourceType == "AuditEventList"`) or query for state-changing actions
>   only using repeated `eventAction` filters (see the recipe below).
> - You cannot suppress these entries server-side via `eventType=` alone —
>   `AUTHORIZATION` also covers other authorization events you may care about.

Example — all state-changing activity in a date window (excludes every `READ`,
which drops both the self-referential audit-log reads *and* other read events),
newest first:

```bash
curl -sS -H "Authorization: Bearer $ARNICA_API_TOKEN" \
  "https://api.app.arnica.io/v1/audit-events?eventAction=CREATE&eventAction=UPDATE&eventAction=DELETE&eventAction=LOGIN&eventAction=LOGOUT&startDate=2026-08-01&endDate=2026-08-18T23:59:59.999Z&limit=100"
```

Example — narrower: only policy and integration UPDATEs made via the API:

```bash
curl -sS -H "Authorization: Bearer $ARNICA_API_TOKEN" \
  "https://api.app.arnica.io/v1/audit-events?eventType=POLICY&eventType=INTEGRATION&eventAction=UPDATE&startDate=2026-08-01&endDate=2026-08-18T23:59:59.999Z&limit=100"
```

Each item (`AuditEventDto`) has this shape (all fields present; nullable ones may
be `null`):

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "timestamp": "2026-08-03T14:30:00.000Z",
  "eventAction": "UPDATE",
  "eventDomain": "PRODUCT",
  "interactionType": "API",
  "user": "security.engineer@example.com",
  "userDisplayName": "Security Engineer",
  "resourceType": "Product",
  "resourceId": "b1e0f1c2-9d1a-4a4e-9d8a-8b3f5b7a1234",
  "resourceName": "Payments Platform",
  "oldValue": { },
  "newValue": { },
  "apiTokenName": "siem-ingestion"
}
```

> Field notes:
> - `eventAction` uses the action enum above; the response field for the domain
>   is `eventDomain` (the *query* parameter that filters it is named `eventType`
>   — the names differ between request and response).
> - `interactionType` is `WEB` or `API` — the interface the action came through.
> - `user` is the actor's email; `userDisplayName` may be `null`.
> - `oldValue` / `newValue` are **full before/after snapshots** of the resource,
>   not a computed diff. To find what actually changed you have to diff them
>   yourself (e.g. `json.dumps(old, sort_keys=True) != json.dumps(new, sort_keys=True)`
>   for a cheap change-check, or `difflib.unified_diff` on canonicalized JSON
>   for a field-level view). For `AUTHENTICATION` events (`LOGIN` / `LOGOUT`)
>   both fields are always `null`.
> - **No-op UPDATE events happen** — clicking "Save" in the web UI without
>   changing anything still writes an `UPDATE` audit entry with
>   `oldValue == newValue`. In a real org sample, ~25% of `POLICY` UPDATEs
>   were no-ops. If you're driving a change-tracking dashboard, filter out
>   `oldValue == newValue` client-side.
> - `apiTokenName` is the *name* of the API key used (e.g. `"skill2"`), not the
>   token value. It is `null` when the action came through the web UI.
> - `resourceId` semantics depend on `resourceType`:
>   - `Policy` → the `PolicySubType` slug (`code_risk`, `secrets`, `global`) —
>     **not** a UUID. Same identifiers as `GET /v1/policies/{subType}`.
>   - `Product` → the product UUID.
>   - `API Key` → the key's name (e.g. `"skill2"`).
>   - `User` → the actor's email.
>   - `AuditEventList` → the Arnica org id.
> - `resourceName` is best-effort human-readable and is often `null` — e.g. for
>   `POLICY` events it was `null` on nearly every historical event in a live
>   sample; Arnica only recently started populating it (Aug 2026) with values
>   like `"Code Risk"`. Never rely on it as a stable filter key — use
>   `resourceType` + `resourceId` instead.

#### Common event shapes

Concrete examples of the most common event types, taken from a live response.
Use these when writing SIEM parsers or dashboards so you know which fields to
expect populated vs. `null`.

**API key created (via WEB)** — `newValue` records the granted scopes; the
`createdBy` field is a redacted email:

```json
{
  "eventAction": "CREATE",
  "eventDomain": "API",
  "interactionType": "WEB",
  "user": "admin@example.com",
  "resourceType": "API Key",
  "resourceId": "skill2",
  "resourceName": null,
  "oldValue": null,
  "newValue": {
    "name": "skill2",
    "scopes": ["risks:read", "audit:read", "products:write"],
    "createdBy": "admi***@***le.com"
  },
  "apiTokenName": null
}
```

**Interactive login (via WEB)** — auth events carry no diff:

```json
{
  "eventAction": "LOGIN",
  "eventDomain": "AUTHENTICATION",
  "interactionType": "WEB",
  "user": "admin@example.com",
  "resourceType": "User",
  "resourceId": "admin@example.com",
  "resourceName": null,
  "oldValue": null,
  "newValue": null,
  "apiTokenName": null
}
```

**Self-referential audit-log read (via API)** — every call to
`GET /v1/audit-events` produces one of these; `newValue.eventCount` is the
number of items that call returned (0 on empty pages, and yes, on the very
call that produced this entry):

```json
{
  "eventAction": "READ",
  "eventDomain": "AUTHORIZATION",
  "interactionType": "API",
  "user": "admin@example.com",
  "resourceType": "AuditEventList",
  "resourceId": "great-rose-c73601",
  "resourceName": "Audit Events",
  "oldValue": null,
  "newValue": { "eventCount": 10 },
  "apiTokenName": "skill2"
}
```

**Policy update (via WEB)** — `resourceId` is the `PolicySubType` slug (not a
UUID), `resourceName` is typically `null`, and `oldValue`/`newValue` are the
full policy document (rules + conditions + triggers), not a diff. The example
below is truncated; a real policy body is easily 5–20 KB:

```json
{
  "eventAction": "UPDATE",
  "eventDomain": "POLICY",
  "interactionType": "WEB",
  "user": "admin@example.com",
  "resourceType": "Policy",
  "resourceId": "code_risk",
  "resourceName": null,
  "oldValue": {
    "sub": "code_risk",
    "rules": [ /* full rule tree before the edit */ ]
  },
  "newValue": {
    "sub": "code_risk",
    "rules": [ /* full rule tree after the edit */ ]
  },
  "apiTokenName": null
}
```

> Policy-specific gotchas:
> - Only `UPDATE` events exist for `POLICY` — policies are singletons per
>   sub-type (`code_risk` | `secrets` | `global`), so you'll never see
>   `CREATE` or `DELETE` in a healthy log.
> - Roughly a quarter of `POLICY` UPDATEs in a live sample were no-ops
>   (`oldValue == newValue`) from the UI's "Save" button.
> - Filter for meaningful changes with e.g.:
>   ```python
>   import json
>   real_changes = [
>       e for e in items
>       if e['eventDomain'] == 'POLICY'
>       and json.dumps(e['oldValue'], sort_keys=True)
>          != json.dumps(e['newValue'], sort_keys=True)
>   ]
>   ```

### 10. Dashboard: Product Risk Totals

The same per-product counts the Arnica risks dashboard shows. One call returns
every product, which makes it the cheapest way to see where the risk is before
pulling findings. See "Findings Query Playbook" below.

#### List Product Risk Totals
```bash
GET /v1/dashboard/product-risk-totals

# Query parameters:
# - minSeverity: critical | high | medium | low   (default: high)
# - minBusinessImportance: high | medium | low   (default: medium)
# - limit: products per page, 1–1000 (default 100)
# - sortBy: importance | name | SCA | SAST | SECRET | IAC | LICENSE | REPUTATION
#           (default importance; a risk type ranks by worst-severity finding
#           of that type)
# - sortOrder: asc | desc (default desc for importance, asc otherwise; for a
#              risk-type sort, asc puts the riskiest products first)
# - cursor: opaque value from the previous response's nextCursor
# Requires scope: dashboard:read
```

Response:

```json
{
  "items": [
    {
      "id": "923660c8-…",
      "name": "payments-api",
      "businessImportance": "high",
      "riskTotals": {
        "sast":       { "critical": 3, "high": 19, "medium": 4 },
        "sca":        { "critical": 0, "high": 0,  "medium": 0 },
        "secret":     { "critical": 0, "high": 13, "medium": 0 },
        "iac":        { "critical": 0, "high": 0,  "medium": 0 },
        "license":    { "critical": 0, "high": 0,  "medium": 0 },
        "reputation": { "critical": 0, "high": 0,  "medium": 0 }
      }
    }
  ],
  "snapshotDate": "2026-10-10T00:00:00.000Z",
  "nextCursor": null
}
```

> Gotchas:
> - **The defaults hide data.** `minBusinessImportance` defaults to `medium`,
>   so low-importance products are left out (on one live tenant: 19 products
>   by default, 75 with `minBusinessImportance=low`). `minSeverity` defaults
>   to `high`, so mediums are left out. Set both explicitly.
> - Severity buckets below `minSeverity` are **omitted**, not zero. A missing
>   key means "filtered out", not "zero".
> - Counts come from the **latest daily snapshot** (`snapshotDate`), not live
>   data. They're for sizing and ranking, not exact counts: on a live tenant a
>   product showing 273 had 236 open findings at the same severities. Report
>   numbers from the findings endpoint.
> - Paginate with `cursor` until `nextCursor` is `null`. Restart without
>   `cursor` if you change `sortBy`/`sortOrder`.

#### Get Risk Totals for One Product
```bash
GET /v1/dashboard/product-risk-totals/product?productId=<uuid>&minSeverity=medium
GET /v1/dashboard/product-risk-totals/product?productName=payments-api
```

> Pass `productId`, `productName` (case-insensitive exact match), or both
> (they must match the same product). Returns `{ "item": {...}, "snapshotDate" }`.
> Ignores business importance. `400` if neither is given or the name matches
> several products (use `productId`), `404` if nothing matches.

### 11. Product Issue Rules & AI SAST Prompt

```bash
# Issue rules: auto-create tickets for a product's findings
GET    /v1/products/{productId}/issues                 # products:read, offset/limit (max 200)
POST   /v1/products/{productId}/issues                 # products:write
PATCH  /v1/products/{productId}/issues/{issueRuleId}   # products:write
DELETE /v1/products/{productId}/issues/{issueRuleId}   # products:write

# IssueRuleCreate: integrationType (jira | jira-datacenter |
#   azure-devops-boards | linear), integrationId, projectId (Jira project key
#   or ADO project UUID), issueTypeId, openStatusId, closedStatusId, fields[]
#   (field mappings). See the Swagger schema for the full field-mapping shape.

# AI SAST: extra prompt appended to AI SAST scans for one product
GET /v1/products/{productId}/ai-sast/prompt    # products:read
PUT /v1/products/{productId}/ai-sast/prompt    # products:write
{ "prompt": "Treat the security-engineering package as trusted input sanitization." }
# max 10000 chars, trimmed, must not be empty
# GET returns { id, productId, prompt }. 404 has two meanings, told apart by
#   the body's message (verified live):
#   "No AI SAST prompt configured for this product." → product exists, no prompt
#   "Product not found."                               → bad product id
#   (a productId that isn't a UUIDv4 → 400 "productId must be a UUIDv4.")
# PUT returns 200 with the same shape and REPLACES the whole prompt (no append)
```

See "Acting on Findings" for how to update the prompt from triage results.

### Not covered here

- `/v1/groups*`: deprecated, replaced by `/v1/products`. Don't use.
- `/v1/risks/ondemand-scan-oauth/*`: OAuth-based on-demand scan endpoints
  (validate, scan an archive, get findings for a repo URL). They use an OAuth
  JWT, not an API key, and their request schemas are empty in the OpenAPI.
  Check the Swagger before using them.

## Common Workflows

### Workflow 1: Analyze Security Findings
```
1. GET /v1/dashboard/product-risk-totals (size the problem, pick products)
2. GET /v1/risks/findings with server-side filters (status, severity, sla,
   type, product), no expand
3. GET /v1/risks/findings/{id}?expand=true only for the findings that need details
4. PUT /v1/risks/{id}/status (update status — OpenAPI calls the path param {sortKey}, but use the finding's `id` field)
```
Follow "Findings Query Playbook" below for steps 1–3.

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

## Findings Query Playbook

Use this whenever the user asks for findings ("show me our criticals",
"what's open in payments", "export findings with SLA"). The findings endpoint
has no total count, pages are capped at 100 (20 with `expand`), and an
org-wide pull can be large: 14,376 findings took **108 s** sequentially on one
live tenant. Working out what the customer needs first, and filtering on the
server, keeps this fast.

### Step 1: Work out what the customer needs

Answer these from the request. Ask only when an answer changes the query and
can't be inferred. Otherwise use the defaults and say which ones you used.

| Question | Query parameter | Default when not stated |
|---|---|---|
| Which statuses? | `status=` (repeatable) | Open: `requires_review`, `pending_review`, `in_progress`, `awaiting_user_input`, `mitigation_in_progress`, `mitigation_pending_pr`, `mitigation_failed` |
| Only findings under SLA? | `sla=true` | `sla=true` for SLA, compliance, or exec reporting. Omit for triage or "everything" |
| Which severities? | `severity=` (repeatable) | `critical`, `high`, `medium`. Add `low` only if asked. Skip `info`/`unknown` |
| Which finding types? | `type=` (repeatable) | All. `SECRET` findings often go to a different team, so ask if the audience is unclear |
| Which products? | `product=<id>` (one per call) | Decide in step 2 |
| One repo/branch? | `asset=` | Only when the user names a repo or works in a checkout |
| Need descriptions, code, CVEs, fix guidance? | `expand=true` | **No.** See step 3 |

Typical requests:

- **"SLA report" / "what's at risk of breaching"**: `status=<open>&sla=true&severity=critical&severity=high&severity=medium`. Use `slaStart` to compute age and compare it with the org's SLA windows. There is no breach filter.
- **"Criticals and highs for product X"**: resolve X to an id with `GET /v1/products?name=X`, then `product=<id>&status=<open>&severity=critical&severity=high`.
- **"Vulnerable dependencies with CVEs"**: `type=SCA&status=<open>`, then expand only the findings you'll show to get `details.vulnerabilities`.
- **"Is anything linked to Jira?"**: no expand needed. `issue` is on every finding.

### Step 2: Look at product risk totals first

Before pulling findings, make one call to see where the risk is:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://api.app.arnica.io/v1/dashboard/product-risk-totals?minSeverity=medium&minBusinessImportance=low&limit=1000"
```

Set `minSeverity` to the lowest severity the user asked for and
`minBusinessImportance=low`, or products will be missing (see the gotchas in
section 10). Sum `riskTotals` per product over the requested types, then decide:

- **Per-product pulls** (preferred): when the user named products, or when
  risk is concentrated (a handful of products hold most of the total). Show
  the user the top products and their totals, and offer to focus on those.
  Per-product pulls are faster in parallel and give a grouped view.
- **One org-wide pull**: when the user wants the whole org and the totals
  are small (roughly under 2,000 matching findings), or when findings outside
  any product matter. Per-product pulls only return findings in repos that
  belong to a product. Every finding has `product: {id, name}` (or `null`),
  so you can still group an org-wide pull by product.

The totals are a daily snapshot and run higher than live open counts. Use
them to choose and rank products, and report numbers from the findings
endpoint.

### Step 3: Decide on `expand`

`expand=true` only adds `details` (see "Response format"). It caps pages at
20 and, measured live, was 3.6× slower with 4× the payload for the same
findings. Default to **no expand**.

| Needed for the answer | Expand? |
|---|---|
| Counts, grouping by severity/type/product/repo, SLA age, owners, links, ticket status, CVSS, reachability, title | No |
| Description, vulnerable code snippet, CWE/OWASP, recommendation | Yes |
| SCA CVE ids or fixed versions (`details.vulnerabilities`, `recommendedV2`) | Yes |
| Secret verification/access details | Yes |

When expand is needed, list without it first, then expand only what you'll
show: `GET /v1/risks/findings/{id}?expand=true` for a short list, or the
filtered list with `expand=true` when you need most of a small product.

### Step 4: Pull products in parallel, 10 at a time

Each product's pages are fetched in order (there's no total, so you page
until a short page), but products are independent. Run up to 10 products at
once. Measured live, 10 products (3,454 findings) took 24.3 s one after
another and 5.3 s 10 at a time, with no `429`s. Process the product list in
chunks of 10 and keep the 429 backoff from "Tips & Best Practices".

```python
import os, json, re, time, random, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

TOKEN = re.search(r"^TOKEN=(.*)$", open(os.path.expanduser("~/.arnica/.prod.env")).read(), re.M).group(1)
BASE = "https://api.app.arnica.io"
OPEN = ["requires_review", "pending_review", "in_progress", "awaiting_user_input",
        "mitigation_in_progress", "mitigation_pending_pr", "mitigation_failed"]

def get(path, params):
    url = f"{BASE}{path}?{urllib.parse.urlencode(params, doseq=True)}"
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == 5:
                raise
            time.sleep(min(30, 2 ** attempt) + random.random())

def findings(filters, expand=False):
    limit, page, out = (20 if expand else 100), 1, {}
    while True:
        params = {**filters, "limit": limit, "page": page}
        if expand:
            params["expand"] = "true"
        batch = get("/v1/risks/findings", params)
        out.update({f["id"]: f for f in batch})       # dedupe: pages can shift
        if len(batch) < limit:
            return list(out.values())
        page += 1

# 1. Rank products by matching risk
severities = ["critical", "high", "medium"]
totals, cursor = [], None
while True:
    params = {"minSeverity": severities[-1], "minBusinessImportance": "low", "limit": 1000}
    if cursor:
        params["cursor"] = cursor
    resp = get("/v1/dashboard/product-risk-totals", params)
    totals += resp["items"]
    cursor = resp["nextCursor"]
    if not cursor:
        break
score = lambda p: sum(n for t in p["riskTotals"].values() for s, n in t.items() if s in severities)
products = sorted((p for p in totals if score(p) > 0), key=score, reverse=True)

# 2. Pull findings per product, 10 products at a time
filters = {"status": OPEN, "severity": severities, "sla": "true"}
results = {}
for i in range(0, len(products), 10):
    chunk = products[i:i + 10]
    with ThreadPoolExecutor(max_workers=10) as pool:
        for p, items in zip(chunk, pool.map(lambda p: findings({**filters, "product": p["id"]}), chunk)):
            results[p["name"]] = items

for name, items in results.items():
    by_sev = {s: sum(f["severity"] == s for f in items) for s in severities}
    print(name, len(items), by_sev)
```

If the user asked about specific products, skip step 1 and pass their ids.
If they only want the top N products, slice `products[:N]` before step 2.

On the live tenant this script pulled 14,074 findings across 74 products in
about 16 s. An org-wide sequential pull with the same filters took 108 s and
returned 14,376. The ~300 extra findings are in repos that belong to no
product. If the user wants org-wide totals, say so, or also run the org-wide pull
and keep the findings whose `product` is `null` (there is no server-side
filter for that). De-duplicate by `id` when merging.

## Acting on Findings: Dismissals, Severity Overrides, and AI SAST Prompt Tuning

Use this when something outside this skill decides what to do with findings
and the API carries it out. That might be a customer's own triage service, an
LLM classifier, a reachability or exploitability engine, or the `arnica-fix`
skill. The API has no approval step: each call takes effect immediately, so
the decisions arrive already made.

| | Use case A + B: per-finding updates | Use case C: product AI SAST prompt |
|---|---|---|
| Scope | One finding at a time | One product, aggregated across all findings handled |
| What you send | A status or severity change, with a **reason that gives the finding's context** | **Directives** for the next scans: what to apply or avoid |
| Who reasons | Arnica reasons from the context you give | You've already reasoned; Arnica follows the instructions |
| When | Applied as decided, failing open | **Only after the user says yes** |

### Use case A: Apply an external process's decisions

**1. Pull the candidates** with the Findings Query Playbook (filters, per
product, no expand unless the decision engine needs `details`). Keep the
listing: its `status`/`severity` are the "before" values for the summary.

**2. Get decisions back in a fixed format**, one record per finding. The
`reason`/`note` follows use case B:

```json
[
  {"id": "<finding id>", "action": "status",
   "status": "dismiss_not_accurate",
   "reason": "The `q` parameter is passed through `@acme/sql-guard` escapeIdentifier() in src/db/query.ts:41 before reaching the query builder, so it can't carry SQL syntax."},
  {"id": "<finding id>", "action": "severity",
   "severity": "low", "reasonCategory": "compensating_control",
   "note": "admin-tools is deployed only to the internal cluster behind the corporate VPN and Okta SSO (deploy/helm/values-prod.yaml); the endpoint isn't reachable from the internet."},
  {"id": "<SCA finding id>", "action": "cve_severity", "cveId": "CVE-2021-23337",
   "severity": "low", "reasonCategory": "reachability",
   "note": "Only lodash.get and lodash.merge are imported (src/utils/*.ts); the vulnerable template() function is never called."}
]
```

**3. Map each decision to the right call.** The status you pick tells the
next reader *why*, so use the most specific one:

| Decision | Call | Value |
|---|---|---|
| False positive (the scanner was wrong) | `PUT /v1/risks/{id}/status` | `dismiss_not_accurate` |
| Real but the risk is acceptable as is, nothing will be done | status | `dismiss_risk_is_tolerable` |
| Real, accepted by an owner | status | `risk_accepted` |
| Real, but no capacity to fix now | status | `dismiss_no_capacity` |
| Secret is not in use (SECRET findings only) | status | `dismiss_secret_not_used` |
| Defer and reopen later | status | `snooze` (no unsnooze date in the body; check the behavior in the UI first) |
| Send back for human triage | status | `requires_review` / `pending_review` |
| Real, should stay tracked, but impact is lower (or higher) in this context. **Not SCA** | `PUT /v1/risks/{id}/severity` | `severity` + `reasonCategory`: `business_asset_context`, `compensating_control`, `org_risk_policy`, `other` |
| SCA: a specific CVE is unreachable or unlikely to be exploited | `PUT /v1/risks/{id}/cves/{cveId}/severity` | `reasonCategory`: `reachability` or `epss` (plus the four above). The finding's severity is then re-derived from its CVEs |

Prefer a **severity override** over a dismissal when the finding is real: it
stays visible and keeps its SLA. Dismiss only when nobody will act on it.

**4. Apply, failing open.** Process every record. Never stop the run on a
bad record or a failed call. Record the result and move on:

- **Skip without calling** (reported as `skipped`) when a record can't
  succeed: `status` outside the write enum, `severity` outside
  `critical | high | medium | low | info`, a `reasonCategory` that doesn't
  match the endpoint (`reachability`/`epss` are CVE-only), an empty
  `reason`, a finding-level `severity` action on an SCA finding, or a
  `cve_severity` action on a non-SCA finding.
- **Call, and record failures** (reported as `failed`) with the HTTP code
  and the `message` from the error body. Expect `400` (invalid body or
  ineligible finding), `403` (key lacks `risks:write`, or manual severity
  override isn't enabled for the org), and `404` (finding or CVE not found).
- Retry only `429`, with backoff. Keep at most 5 calls in flight.
- Success is `204` (reported as `changed`).

```python
import json, time, random, urllib.parse, urllib.request, urllib.error
from collections import Counter

WRITE_STATUSES = {"resolved", "in_progress", "requires_review", "pending_review", "risk_accepted",
                  "dismiss_no_capacity", "dismiss_not_accurate", "dismiss_risk_is_tolerable",
                  "dismiss_secret_not_used", "snooze"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
REASONS = {"business_asset_context", "compensating_control", "org_risk_policy", "other"}

def call(method, path, body, token):
    req = urllib.request.Request(
        f"https://api.app.arnica.io{path}", method=method, data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, None
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 5:
                time.sleep(min(30, 2 ** attempt) + random.random())
                continue
            try:
                msg = json.loads(e.read()).get("message")
            except Exception:
                msg = None
            return e.code, msg
        except urllib.error.URLError as e:
            return None, str(e.reason)

def plan(d, finding):
    """Return (method, path, body) or raise ValueError(reason to skip)."""
    enc = urllib.parse.quote(d["id"], safe="")
    is_sca = finding.get("type") == "SCA"
    if d["action"] == "status":
        if d.get("status") not in WRITE_STATUSES or not d.get("reason"):
            raise ValueError("invalid status or empty reason")
        return "PUT", f"/v1/risks/{enc}/status", {"status": d["status"], "reason": d["reason"]}
    body = {k: d[k] for k in ("severity", "reasonCategory", "note") if d.get(k)}
    if d.get("severity") not in SEVERITIES:
        raise ValueError("invalid severity")
    if d["action"] == "severity":
        if is_sca:
            raise ValueError("finding-level severity override isn't allowed on SCA; use cve_severity")
        if d.get("reasonCategory") not in REASONS:
            raise ValueError("invalid reasonCategory")
        return "PUT", f"/v1/risks/{enc}/severity", body
    if d["action"] == "cve_severity":
        if not is_sca or not d.get("cveId"):
            raise ValueError("cve_severity needs an SCA finding and a cveId")
        if d.get("reasonCategory") not in REASONS | {"reachability", "epss"}:
            raise ValueError("invalid reasonCategory")
        cve = urllib.parse.quote(d["cveId"], safe="")
        return "PUT", f"/v1/risks/{enc}/cves/{cve}/severity", body
    raise ValueError(f"unknown action {d['action']!r}")

def apply(decisions, findings_by_id, token):
    results = []
    for d in decisions:
        f = findings_by_id.get(d["id"], {})
        r = {"id": d["id"], "action": d["action"], "product": (f.get("product") or {}).get("name"),
             "title": f.get("title"), "before": {"status": f.get("status"), "severity": f.get("severity")},
             "after": {k: d[k] for k in ("status", "severity", "cveId") if k in d}}
        try:
            method, path, body = plan(d, f)
        except (ValueError, KeyError) as e:
            results.append({**r, "outcome": "skipped", "error": str(e)})
            continue
        code, msg = call(method, path, body, token)
        results.append({**r, "outcome": "changed" if code == 204 else "failed", "http": code, "error": msg})
    return results

def summarize(results):
    print(Counter(r["outcome"] for r in results))
    changed = [r for r in results if r["outcome"] == "changed"]
    print("changed by action/value:", Counter((r["action"], r["after"].get("status") or r["after"].get("severity")) for r in changed))
    print("changed by product:", Counter(r["product"] for r in changed))
    for r in results:
        if r["outcome"] != "changed":
            print(r["outcome"], r.get("http"), r["id"], "-", r["error"])
```

**5. Summarize for the user**: counts of changed / failed / skipped; what
changed, grouped by action and new value, by product, and before → after
for severity changes; and every failed or skipped finding with its id, title,
and the error or skip reason, so it can be fixed and resent. End with the
developer feedback loop callout from use case B for every product that had
dismissals.

Use a dedicated API key for each automation so its changes can be told apart
from human ones.

### Use case B: Explain the finding's context in the reason

The `reason` (status) or `note` (severity) is where you tell Arnica **why**,
so it can reason about this finding and similar ones. Write it about the
finding's context only, the facts that make it not exploitable or less
severe *here*:

- **A security control in the code:** "Input to `render()` goes through
  `@acme/html-sanitizer` sanitize() (src/web/render.ts:22), which strips
  script and event-handler attributes."
- **Deployment environment with compensating controls:** "The service runs
  only in the internal `ops` cluster behind the VPN and mTLS
  (deploy/k8s/ops/ingress.yaml); there is no public ingress."
- **Unreachable path:** "`scripts/migrate_2019.py` is a one-off migration
  that isn't packaged in the Docker image (see .dockerignore) and never runs
  in production."
- **Unreachable vulnerable code (SCA):** "Only `yaml.safe_load` is used
  (grep across src/); the vulnerable `yaml.load` path is never called."

Rules:
- State the context and point to the evidence (file, package, config,
  environment). Don't stop at a verdict: "false positive" or "not
  exploitable" on its own gives Arnica nothing to reason with.
- Keep it about the finding. Leave out process details (who decided, run
  ids, ticket numbers, team names) and anything unrelated to why this
  finding is or isn't a risk.
- Don't tell Arnica what to do in the reason ("stop reporting this"). That's
  use case C.
- No secrets, credentials, tokens or customer data in the text.

> **When you're done: examine the developer feedback loop in each affected product.**
> After use case B, or any run that dismisses findings (any `dismiss_*`
> status, `risk_accepted`, `snooze`, or a severity downgrade), tell the user
> to review the developer feedback loop in Arnica for every product that had
> dismissals. List those products and the number of dismissals in each. This
> is a callout in your response, not an API action. The context that
> justified the dismissals usually means developers in that product are
> getting, or will get, the same signal again: PR comments, status checks,
> notifications and linked tickets. The user should check whether that
> feedback is still accurate and useful for the product. If the same context
> explains many dismissals, also point them to use case C.

### Use case C: Turn aggregated learnings into the product's AI SAST prompt

After a run, look at **all the findings handled in one product** and their
use case B reasons. When the same context explains several of them, turn it
into an instruction in the product's AI SAST prompt, so future scans apply
it from the start. B gives Arnica context and lets it reason. C is the
conclusion: it tells Arnica specifically what to apply or avoid.

1. **Aggregate per product.** Group the run's results by `product` and,
   within a product, by shared cause (the same sanitizer package, the same
   deployment control, the same unreachable path). One finding is an
   anecdote. Several findings with the same cause make a learning.
2. **Write each learning as a scoped directive** saying what to apply or
   avoid, where, and why:
   - "Treat `@acme/sql-guard` escapeIdentifier()/escapeValue() as SQL
     sanitizers. Don't report SQL injection where the tainted value passes
     through them before reaching the query."
   - "Don't report findings under `scripts/migrations/`. These are one-off
     scripts excluded from the production image."
   - "Services under `services/admin-*` run only on the internal cluster
     behind VPN + SSO. Lower internet-exposure findings there to low unless
     they allow authentication bypass."
   - "Apply extra scrutiny to `api/public/`. It's internet-facing and
     handles payment data."
   Scope every directive to a package, path, service or environment. Never
   write blanket suppressions ("don't report SQL injection").
3. **Read the current prompt:** `GET /v1/products/{productId}/ai-sast/prompt`
   → `{id, productId, prompt}`. A `404` can mean two things. Tell them apart
   by `message`:
   - `"No AI SAST prompt configured for this product."` → start from an
     empty prompt.
   - `"Product not found."` → wrong product id; skip this product.
4. **Merge.** PUT replaces the whole prompt, so build the full new text:
   keep every existing instruction (including non-learning ones, such as
   formatting requirements for finding descriptions), add the new
   directives, and flag any directive that contradicts an existing line
   instead of silently replacing it. Remove duplicates. The result must be
   under 10,000 characters and non-empty after trimming.
5. **Ask the user whether to apply it.** For each product, show the current
   prompt, the proposed prompt (or a diff), and for each new directive the
   number of findings and a short summary of the evidence behind it. Apply
   only the products the user approves. They may edit or drop directives.
6. **Apply** with `PUT /v1/products/{productId}/ai-sast/prompt` and
   `{"prompt": "<merged text>"}`. `200` returns the saved prompt. Same
   fail-open rule as use case A: record failures, continue with the next
   product, and include them in the summary.
7. **Set expectations.** The prompt affects future AI SAST scans of that
   product only. Existing findings are changed by use case A, not by the
   prompt. After the next scan, check that the targeted noise is gone and
   that real issues in the same areas are still reported.

Don't copy one product's directives into another product's prompt unless the
user confirms the same context holds there.

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
- `status=<FindingStatuses>` — see "Safe status updates" below for the full enum; use `requires_review` to focus on actionable issues, or the open set in "Findings Query Playbook"
- `asset=<asset-string>` to scope to a specific repo/branch
- `product=<productId>` to scope to all assets of a product
- `sla=<bool>` — **whether the finding has an SLA**, not whether it's breached. Verified live: `sla=true` returns only findings with a non-null `slaStart`; `sla=false` returns only findings with `slaStart: null`. There is no "breached" filter; compute it client-side from `slaStart` plus your org's SLA window
- `secretType=...` and `secretValidation=...` for secret-finding refinement
- `expand=true` for full details (caps page size at 20)
- `page` / `limit` for pagination

Combine repeated parameters for multiple values:

```
severity=critical&severity=high&type=SAST&type=SCA
```

### Expand and pagination

`limit` defaults to **20** and is capped at **100** server-side (values above 100 are silently clamped, not rejected). `limit=100` works even though the OpenAPI marks 100 as an exclusive maximum. `page` defaults to **1**.

When `expand=true`, the page size is further capped at **20** regardless of what you send for `limit`.

**`expand=true` adds exactly one field: `details`.** Everything else (title,
severity, status, type, asset, product, SLA fields, permalink, reachability,
CVSS, linked issue) is already on the non-expanded response. Measured on a live
tenant: one expanded finding is ~23× larger; pulling the same 235 findings took
7.2 s expanded and 2.0 s non-expanded. See "Findings Query Playbook" for when
expand is worth it.

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

Fields on every finding **without** `expand` (verified live): `id`, `title`,
`type`, `severity`, `status`, `asset`, `product` (`{id, name}` or `null`),
`firstDetected`, `lastDetected`, `lastUpdated`, `resolvedAt`, `slaStart`,
`slaTimeToRemediationInMinutes`, `timeToRemediationInMinutes`, `permalink`,
`issue` (`{type, key, url}` of a linked Jira/ADO ticket, or `null`),
`reachability`, `highestCvssScore`, `vulnerabilityClass`, `checkId`,
`codeLanguage`, `lineNumber`, `isAiSast`, `isAiAdjusted`, `isDevDependency`,
`hasDirectVulnerabilities`, `latestVersion`, `dismissalReason`,
`snoozeReason`, `unsnoozeDate`, `activity`, `detectedIn`, `scannedIn`.

With `expand=true`, findings also include a `details` object. Its keys depend on `type` (verified live):

| Type | `details` keys |
|---|---|
| SAST | `description`, `code`, `ruleId`, `cwe`, `owasp`, `references`, `recommendation` |
| SCA | `description`, `package`, `packageType`, `version`, `vulnerabilities` (CVE list), `recommendedV2` |
| IAC | `description`, `code`, `reference` |
| SECRET | `description`, `type`, `verification`, `accessed` |
| LICENSE | `description`, `package`, `packageType`, `licenses`, `preferred` |
| REPUTATION | `description`, `package`, `packageType`, `openssf`, `stars`, `weeklyDownloads`, `releases`, `dependents`, `firstPublished`, `lastPublished` |

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
`requires_review`, `pending_review`, `in_progress`, `snooze`, `awaiting_user_input`,
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
- `snooze`

Anything in the read enum but not the write enum is system-managed and cannot be set via the API (e.g. `*_automatically`, `awaiting_user_input`, `mitigation_*`, `dismiss_no_option_chosen_yet`).

### Approval / triage guidance
For code-review and triage workflows, always verify findings before changing status.
For bulk or automated changes, follow "Acting on Findings" above.
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
- `inventory:read` - View repository inventory and path exclusions
- `sbom-api:read` - Check SBOM scan status
- `sbom-api:write` - Upload SBOM scans
- `policies:read` - View security policies
- `status-checks:read` - View CI/CD status checks
- `audit:read` - Read the organization audit-event log
- `dashboard:read` - Read product risk totals (`/v1/dashboard/*`)
- `inventory:write` - Replace repository path exclusions

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

> Note: For most endpoints Arnica does **not** use HTTP `401` for invalid bearer tokens — it returns `403 Forbidden`. The one documented exception is `GET /v1/audit-events`, which returns `401` for a *missing* API key (but still `403` for an invalid key or a key missing `audit:read`). Outside audit-events, don't write code that branches specifically on `401`.

## Tips & Best Practices

1. **Token Management**: Use environment variables, never commit tokens
2. **Rate Limiting**: On `429` responses, back off with exponential delay + jitter (suggested: start at 1s, double on each retry, max 30s, cap at 5 retries). When fanning out parallel requests, keep concurrency bounded: up to 10 in-flight requests for per-product findings pulls (see "Findings Query Playbook"), 5 for anything else.
3. **Pagination**: Use `offset`/`limit` for `/v1/products` and `/v1/audit-events`, and `page`/`limit` for `/v1/risks/findings` (each endpoint's parameters are listed in its section above). For `/v1/audit-events` you can also page against the returned `total`; elsewhere, paginate until a page is shorter than the requested limit.
4. **Filtering**: Filter on API side when possible, not in application. Skip `expand=true` unless you need `details`
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

# Page through findings (response is a flat JSON array, not a wrapped object;
# there is no total, so stop on a short page)
findings, page = [], 1
while True:
    response = requests.get(
        f"{BASE_URL}/v1/risks/findings",
        headers=headers,
        params={"status": "requires_review", "limit": 100, "page": page},
    )
    response.raise_for_status()
    batch = response.json()  # list[dict]
    findings += batch
    if len(batch) < 100:
        break
    page += 1

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
