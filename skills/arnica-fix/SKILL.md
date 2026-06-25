---
name: arnica-fix
description: >-
  Triage code security findings from Arnica (SAST, SCA, IaC, CI/CD security,
  etc. — everything except secrets) by correlating them to source code,
  classifying as true or false positive, fixing true positives, and dismissing
  false positives via API. Use when the user asks to review, triage, fix, or
  dismiss security findings, code risks, or Arnica findings.
---

# Code Finding Triage

Systematic workflow for triaging code security findings from Arnica's API.
Covers all finding types — SAST, SCA (vulnerable dependencies), IaC
misconfigurations, CI/CD pipeline security, code reputation — **except secrets**
(which have a separate workflow).

Fetch findings, correlate to source, classify, then **ask the user** before
making any changes or API calls.

**CRITICAL: Every side-effect is gated. There are three approval gates — Gate 0
(branch scope), Gate 1 (fix approval), Gate 2 (dismiss/accept approval). Never
edit code or call the dismiss/status API without the user's explicit go-ahead.**

## Scope

| Covered | Not covered |
|---|---|
| `SAST`, `SCA`, `IAC`, `LICENSE`, `REPUTATION` findings | `SECRET` findings — use the secrets workflow instead |
| `severity = critical \| high \| medium \| low` | `severity = info \| unknown` — informational / non-actionable |
| Repo + branch scoped triage (`asset=…` filter) | Org-wide reporting / dashboards |

## Related skills

- **`arnica-api`** (required): endpoint reference, auth, pagination, error
  model, and the writable status enum. This skill assumes `arnica-api` is
  loaded — most low-level details defer there.

## Prerequisites

- Arnica API token at `~/.arnica/.prod.env` as `TOKEN=arnica_...`. See the
  `arnica-api` skill for token setup, validation, and storage rules.
- Token scopes: `risks:read` (fetching) and `risks:write` (dismissing/updating).
- API base: `https://api.app.arnica.io` — see the `arnica-api` skill for the
  full endpoint reference, error model, and pagination semantics.
- Token loading convention (matches `arnica-api`):
  ```bash
  TOKEN=$(grep '^TOKEN=' ~/.arnica/.prod.env | cut -d= -f2)
  ```

## Building the `asset` query parameter

The `GET /v1/risks/findings` endpoint accepts an `asset` query parameter to
filter findings to a specific repo/branch. The format is:

```
{scm}:{organization}/{project}/{repo}#{branch}
```

You **must** construct this from the current git repo. Follow these steps:

### 1. Get the git remote URL and current branch

```bash
REMOTE_URL=$(git remote get-url origin)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
```

### 2. Determine the SCM type from the remote URL

| Remote URL pattern | SCM type |
|---|---|
| `github.com` | `github` |
| `dev.azure.com` or `*.visualstudio.com` | `azure-devops` |
| `gitlab.com` | `gitlab` |
| `bitbucket.org` | `bitbucket-cloud` |
| Any other self-hosted Bitbucket (Stash) | `bitbucket-server` |
| Any other self-hosted GitLab | `gitlab` |

**If the SCM type is ambiguous** (e.g. a self-hosted domain that could be GitLab,
Bitbucket Server, or even GitHub Enterprise), **do not give up**. Instead:

1. Extract org/repo from the URL path segments as best you can.
2. Build candidate asset strings for **every plausible SCM type** (e.g. `gitlab`,
   `bitbucket-server`, `github`). For each, try both the with-project and
   without-project variants where applicable.
3. Call the API with each candidate asset string. The first one that returns
   findings (non-empty results) is the correct SCM type.
4. Only ask the user if **none** of the candidates return results.

### 3. Extract organization, project, and repo

**The rules differ by SCM type.** The key distinction is whether the SCM has a
"project" level between organization and repo.

| SCM type | Has project? | Remote URL example | org | project | repo |
|---|---|---|---|---|---|
| `github` | **No** | `github.com/my-org/my-repo.git` | `my-org` | _(empty)_ | `my-repo` |
| `azure-devops` | **Yes (required)** | `dev.azure.com/my-org/my-project/_git/my-repo` | `my-org` | `my-project` | `my-repo` |
| `gitlab` | Optional (subgroup) | `gitlab.com/my-group/my-repo.git` | `my-group` | _(empty or subgroup)_ | `my-repo` |
| `bitbucket-cloud` | **Yes (required)** | `bitbucket.org/workspace/my-repo.git` | `workspace` | `project-key` | `my-repo` |
| `bitbucket-server` | **Yes (required)** | `bitbucket.mycompany.com/scm/PROJ/my-repo.git` | `https://bitbucket.mycompany.com` | `PROJ` | `my-repo` |

**Extraction by SCM type:**

**GitHub** (`github.com/{org}/{repo}.git`):
```bash
ORG=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|')
REPO=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/][^/]+/([^/.]+)(\.git)?$|\1|')
PROJECT=""
```

**Azure DevOps** (`dev.azure.com/{org}/{project}/_git/{repo}`):
```bash
ORG=$(echo "$REMOTE_URL" | sed -E 's|.*dev\.azure\.com/([^/]+)/.*|\1|')
PROJECT=$(echo "$REMOTE_URL" | sed -E 's|.*dev\.azure\.com/[^/]+/([^/]+)/_git/.*|\1|')
REPO=$(echo "$REMOTE_URL" | sed -E 's|.*/_git/([^/.]+)(\.git)?$|\1|')
```

**GitLab** (`gitlab.com/{group}[/{subgroup}]/{repo}.git`):
```bash
# For top-level group repos: org=group, project="" (empty)
# For subgroup repos: org=group, project=subgroup
PATH_PART=$(echo "$REMOTE_URL" | sed -E 's|.*gitlab\.com[:/](.+?)(\.git)?$|\1|')
ORG=$(echo "$PATH_PART" | cut -d/ -f1)
REPO=$(echo "$PATH_PART" | rev | cut -d/ -f1 | rev)
# project is everything between org and repo (may be empty)
PROJECT=$(echo "$PATH_PART" | sed -E "s|^$ORG/||; s|/$REPO$||")
```

**Bitbucket Cloud** (`bitbucket.org/{workspace}/{repo}.git`):
```bash
ORG=$(echo "$REMOTE_URL" | sed -E 's|.*bitbucket\.org[:/]([^/]+)/.*|\1|')
REPO=$(echo "$REMOTE_URL" | sed -E 's|.*bitbucket\.org[:/][^/]+/([^/.]+)(\.git)?$|\1|')
# The project key isn't in the clone URL — fetch it from the Bitbucket UI
# or from the `asset.project` field of an existing finding (see Bitbucket
# Server caveat in the arnica-api skill).
PROJECT=""  # FILL THIS IN — required for bitbucket-cloud
```

**Bitbucket Server / Stash** (`{base-url}/scm/{PROJ}/{repo}.git`):
```bash
# org = URL-encoded server base URL (https://server.fqdn.com → https%3A%2F%2Fserver.fqdn.com)
BASE_URL=$(echo "$REMOTE_URL" | sed -E 's|^(https?://[^/]+)/.*|\1|')
ORG=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$BASE_URL")
PROJECT=$(echo "$REMOTE_URL" | sed -E 's|.*/scm/([^/]+)/.*|\1|')
REPO=$(echo "$REMOTE_URL" | sed -E 's|.*/scm/[^/]+/([^/.]+)(\.git)?$|\1|')
```

> **Bitbucket Server tenant variance**: the URL-encoded-base-URL format isn't
> in the OpenAPI spec and varies by tenant. If the constructed asset returns
> zero results, inspect a real finding's `asset` shape per the BBS caveat in
> the `arnica-api` skill, then build the asset string from those exact values.

### 4. Construct the asset string

**Critical: the asset format always has exactly 3 path segments** (`org/project/repo`).
When there is no project (e.g. GitHub), use an **empty string** for the project
segment, resulting in a double-slash `//`:

```
github:my-org//my-repo#main
```

For SCMs with a project:
```
azure-devops:my-org/my-project/my-repo#main
```

General construction:
```bash
ASSET="${SCM_TYPE}:${ORG}/${PROJECT}/${REPO}#${BRANCH}"
```

> **CRITICAL footgun — URL-encode `$ASSET` before putting it in the query
> string.** The asset value contains `:`, `/`, and `#`. The `#` is a URL
> fragment delimiter — if you interpolate the raw value, everything after
> `#` (i.e. the branch name) is silently stripped before the request leaves
> your machine, and the API will return findings for the wrong branch (or
> none). Even when shell-quoted, the `#` still breaks at the URL layer. Always
> encode:
>
> ```bash
> ASSET_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ASSET")
> # Use ${ASSET_ENC} (not ${ASSET}) inside any URL.
> ```

### 5. Complete examples

| SCM | Asset string |
|---|---|
| GitHub | `github:my-org//my-repo#main` |
| Azure DevOps | `azure-devops:Pasture/Goats/GitGoat#main` |
| GitLab (no subgroup) | `gitlab:my-group//my-repo#main` |
| GitLab (with subgroup) | `gitlab:my-group/my-subgroup/my-repo#main` |
| Bitbucket Cloud | `bitbucket-cloud:workspace/project-key/my-repo#main` |
| Bitbucket Server | `bitbucket-server:https%3A%2F%2Fserver.fqdn.com/PROJ/my-repo#main` |

**Note:** For Bitbucket Server, the organization is the server base URL and must
be URL-encoded (`:` → `%3A`, `/` → `%2F`).

---

## Workflow-specific API notes

> Full endpoint reference (auth, error model, products/assets/owners/SBOM/etc.)
> lives in the `arnica-api` skill. The bits below are what the triage workflow
> actually depends on.

### Filtering parameters used by this workflow

| Parameter | Type | Description |
|---|---|---|
| `asset` | string | Filter by asset (see above) |
| `severity` | string[] | **Exact match** — `severity=high` returns ONLY high, NOT critical+high. Pass each level explicitly. Values: `critical`, `high`, `medium`, `low`, `info` |
| `type` | string[] | Finding type. Values: `SAST`, `SCA`, `IAC`, `LICENSE`, `REPUTATION` (skip `SECRET`) |
| `status` | string[] | Filter by status (e.g. `requires_review`) |
| `expand` | boolean | Include full details. **Caps page size to 20** when `true` (`limit` values above 20 are silently clamped). |
| `limit` | number | Page size. Server default **20**, server max **100** (values above 100 are silently clamped). With `expand=true` the cap drops to **20**. This skill always uses `expand=true` + `limit=20`. |
| `page` | number | Page number (1-based) |
| `product` | string | Alternative scoping: filter by Arnica product ID instead of by `asset`. Useful when triaging by team/product ownership rather than by repo. |

Multiple values for `severity` and `type` use repeated params:
`severity=critical&severity=high&type=SAST`

### Response shape this workflow reads

The API returns a **flat JSON array** of finding objects. Fields the triage
workflow correlates to source and uses for classification:

| Field | Description |
|---|---|
| `id` | Finding ID — needed for dismiss/status PUT and for `GET /v1/risks/findings/{id}` |
| `title` | Human-readable finding title |
| `type` | Finding type: `SAST`, `SCA`, `IAC`, `LICENSE`, `REPUTATION` |
| `severity` | `critical` / `high` / `medium` / `low` |
| `status` | Current state (e.g. `requires_review`, `in_progress`, `dismissed`) |
| `checkId` | Rule/CVE that triggered (e.g. `arn.ai.typescript.injection`, `CVE-2023-xxxxx`, `CKV_AWS_18`) — group large batches by this |
| `asset.path` | File path within the repo |
| `asset.repo` | Repository name |
| `asset.branch` | Branch name |
| `lineNumber` | Line number in the file |
| `file` | URL to the file in the SCM (clickable link) |
| `permalink` | Direct link to the finding in the Arnica UI |
| `firstDetected` | When the finding was first seen |
| `dismissalReason` | Reason if previously dismissed |
| `reachability` | Reachability context (SCA only, may be null) |

### Expanded details (`expand=true`)

`expand=true` enriches each finding with a `details` object whose shape varies
by finding type — these are the fields classification depends on:

| Finding type | `details` fields used during triage |
|---|---|
| **SAST** | `description`, `code` (snippet), `ruleId`, `references`, `cwe`, `owasp`, `recommendation` |
| **SCA** | `description`, `package`, `packageType`, `version`, `vulnerabilities`, `recommendedV2` (safe version) |
| **IaC** | `description`, `code` (snippet), `reference` |
| **License** | `description`, `preferred`, `licenses`, `package`, `packageType` |
| **Reputation** | `description`, `package`, `packageType`, `stars`, `releases`, `dependents`, `weeklyDownloads`, `openssf` |

The same `details` are also available via `GET /v1/risks/findings/{id}?expand=true`
if you need to refetch a single finding.

### Dismiss/update statuses (workflow-allowed subset)

Endpoint syntax, URL-encoding rules for the finding `id`, and the full
read/write enums are in the `arnica-api` skill (`PUT /v1/risks/{id}/status`).
The triage workflow uses these writable statuses:

- `dismiss_not_accurate` — false positive, scanner got it wrong
- `dismiss_no_capacity` — true but won't fix now
- `dismiss_risk_is_tolerable` — tolerable risk
- `risk_accepted` — acknowledged and accepted
- `in_progress` — being worked on
- `resolved` — manually mark as fixed. Prefer letting Arnica auto-resolve once
  the fix lands on the tracked branch; only set `resolved` manually when the
  fix shipped on an untracked branch / external repo, or the scanner won't
  detect the fix automatically.
- `requires_review` — **rollback**: undo a wrong dismissal/acceptance and
  return the finding to the triage queue.

Both `status` and `reason` are required. A successful update returns HTTP 204.

---

## Workflow

The workflow processes findings in batches organized by **severity** (descending)
then by **finding type**. This ensures the most critical issues are addressed
first, and each batch is small enough to triage carefully.

> **Why severity-first instead of type-first?** Severity-first guarantees the
> most exploitable issues are addressed before any medium/low work, even if it
> means context-switching between scanner types. Type-first (e.g. "all SAST,
> then all SCA") is friendlier to specialist owners but lets a critical SCA
> sit while you wade through low SAST. This skill is opinionated about
> severity-first; if a team needs type-first, override at Gate 0.

**Processing order:**

```
For each severity in [critical, high, medium, low]:
  For each type in [SAST, SCA, IAC, LICENSE, REPUTATION]:
    → Fetch → Triage → Gate 1 (fix) → Fix → Gate 2 (dismiss) → Dismiss
    → THEN move to the next type/severity
```

**One type at a time. Finish the full cycle before starting the next batch.**
Skip any severity/type combination that returns zero findings. Skip `SECRET`
type entirely (secrets have a separate workflow). Skip `info` and `unknown`
severities (informational / non-actionable — surface them in the final summary
only if the user asks).

```
- [ ] Step 0: Build asset string from current git repo
- [ ] **GATE 0: User chooses branch scope**
- [ ] **Batch loop** (one severity + one type per iteration):
  - [ ] Step 1: Fetch findings with expand=true (20 per page)
  - [ ] Step 2: Process pages (read source + correlate) — subagents for multi-page
  - [ ] Step 3: Classify and present triage table
  - [ ] **GATE 1: User approves what to fix for THIS batch**
  - [ ] Step 4: Fix approved true positives in code
  - [ ] Step 5: Verify fixes (build + test)
  - [ ] **GATE 2: User approves what to dismiss for THIS batch**
  - [ ] Step 6: Dismiss/update approved findings via API
  - [ ] Step 7: Verify batch results → move to next type/severity
- [ ] Step 8: Final summary across all batches
```

---

### Step 0: Build the asset string

Run git commands to determine the SCM type, organization, project, and repo
from the current repository's remote URL. Also detect:

- **Current branch**: `git rev-parse --abbrev-ref HEAD`
- **Default branch**: `git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|refs/remotes/origin/||'`
  (falls back to `main` or `master` if the above fails — check which exists
  with `git rev-parse --verify origin/main` / `git rev-parse --verify origin/master`)

Construct the `asset` query parameter following the rules in "Building the
`asset` query parameter" above, but **do not fill in the branch yet** — that
depends on the user's choice in Gate 0.

If the SCM type is ambiguous (self-hosted / unrecognized domain), build multiple
candidate asset strings and try each one against the API in Step 1. Use the
first candidate that returns results. Do **not** ask the user to tell you the
SCM type until you have exhausted all plausible candidates.

### GATE 0 — User chooses branch scope

**Before fetching findings**, decide the branch scope:

- **If `current branch == default branch`** (very common, e.g. you're already
  on `main`): skip the question entirely. Use that branch and announce
  _"Triaging `<branch>` (current = default)."_ Move straight to the batch loop.
- **Otherwise**: present the user with a structured choice using the
  AskQuestion tool:

**Question: "Which branch's findings should be triaged?"**

Options:
- **Current branch** (`<detected branch name>`) — findings on the branch you
  are currently working on
- **Default branch** (`<detected default branch>`) — findings on the repo's
  main/default branch
- **Other** — let the user type a branch name (use this if they want to triage
  a specific feature/release branch)

Use the user's selection to set the `#branch` suffix in the asset string.

---

## Batch loop (one finding type at a time)

**Each batch is ONE severity + ONE finding type.** Complete the entire cycle
for that batch (fetch → triage → fix → dismiss) before moving to the next.
Do NOT combine multiple types or severities into a single batch.

**Processing order:**

```
1. critical SAST   → full cycle (fetch, triage, fix, dismiss)
2. critical SCA    → full cycle
3. critical IAC    → full cycle
4. critical LICENSE    → full cycle
5. critical REPUTATION → full cycle
   ── SEVERITY CHECKPOINT: ask user whether to continue to high ──
6. high SAST       → full cycle
7. high SCA        → full cycle
...and so on for medium, low (with checkpoints between each severity)
```

Before starting each batch, announce it clearly:
_"Processing **critical SAST** findings..."_

Skip any combination that returns zero findings — just move to the next.

**Severity checkpoint:** After completing ALL types within a severity level,
present a brief summary of what was done and ask the user whether to continue:

> **Critical severity complete: 6 SAST (1 fixed, 5 dismissed), 17 SCA (0 fixed,
> 0 dismissed). Next up: high severity (~160 findings across SAST, SCA, IAC,
> REPUTATION). Continue?**

Options:
- **Continue to high severity**
- **Skip to final summary** — stop here and show results so far

This gives the user a natural exit point without abandoning work mid-batch.

**Do NOT:**
- Combine "all critical findings" into one batch
- Ask about multiple types in a single question
- Bundle dismiss decisions across different types
- Preview upcoming batches before finishing the current one

### Step 1: Fetch findings with details (expand=true, page by page)

Always use `expand=true` on the list endpoint to get full details (code
snippets, CWE, remediation, CVE info, etc.) in a single request per page.
This avoids N+1 API calls.

**Important:** `expand=true` caps pages at **20 results**. Use `limit=20` and
paginate through all pages.

**Filter by `status=requires_review`** to only fetch actionable findings.
This skips findings that are already dismissed, resolved, or in-progress —
avoiding re-triaging work that's already been done.

```bash
TOKEN=$(grep '^TOKEN=' ~/.arnica/.prod.env | cut -d= -f2)
# IMPORTANT: URL-encode $ASSET — see the asset-encoding callout in Step 0.
ASSET_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$ASSET")
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.app.arnica.io/v1/risks/findings?asset=${ASSET_ENC}&severity=${SEVERITY}&type=${TYPE}&status=requires_review&expand=true&limit=20&page=1"
```

Example for critical SAST (with `ASSET_ENC` set as above):
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.app.arnica.io/v1/risks/findings?asset=${ASSET_ENC}&severity=critical&type=SAST&status=requires_review&expand=true&limit=20&page=1"
```

If zero findings on page 1, skip to the next batch.

**Pagination:** The API does not return a total count. Keep fetching pages
until a page returns **fewer than 20 results** (that's the last page).
If page 1 returns exactly 20, there may be more — fetch page 2, etc.

### Step 2: Process pages and correlate to source

The parent agent already has page 1 from Step 1. For each page of findings:

1. Read all source files referenced by findings on that page
2. Correlate each finding to its source line (match by line number, or by
   nearby code pattern if the line has shifted)

**Multi-page batches:** If page 1 returned 20 results (meaning more pages
exist), dispatch **parallel subagents** for pages 2, 3, etc.

- **Subagent type**: use `explore` (read-only — perfect for fetch + correlate;
  prevents accidental writes from a subagent).
- **Bounded parallelism**: cap at **5 in-flight subagents** to avoid hitting
  Arnica `429` rate limits. For batches with more than 5 remaining pages,
  dispatch in waves of 5.
- **What each subagent must return** (so the parent can merge cleanly):
  a JSON-ish list of `{ id, title, severity, type, asset.path, lineNumber,
  classification, confidence, reasoning }`.

Subagent prompt template (parameterize `<PAGE>`, `<SEVERITY>`, `<TYPE>`,
`<ASSET_ENC>`):

```
Fetch page <PAGE> of Arnica findings:
  curl -s -H "Authorization: Bearer $(grep '^TOKEN=' ~/.arnica/.prod.env | cut -d= -f2)" \
    "https://api.app.arnica.io/v1/risks/findings?asset=<ASSET_ENC>&severity=<SEVERITY>&type=<TYPE>&status=requires_review&expand=true&limit=20&page=<PAGE>"
For each finding: read the file at asset.path, correlate to lineNumber, and
classify per the arnica-fix skill's "Step 3" rules. Return the structured
list described above. Do NOT modify any files. Do NOT call any PUT endpoints.
```

The parent processes page 1 inline while subagents handle remaining pages
in waves. Once all pages are done, merge results and proceed to Step 3.

For small batches (1 page / ≤20 findings), no subagents needed — do
everything inline.

### Step 3: Classify and present triage table

**Large batches (50+ findings):** If a severity + type combination has many
findings, group them by `checkId` (rule/CVE) and process one rule group at a
time within the batch. Many findings from the same rule often share the same
verdict (e.g. 40 injection findings where 38 are the same false positive
pattern). Present each rule group, let the user approve fixes/dismissals for
that group, then move to the next rule group. This keeps triage tables
manageable and lets the user apply consistent decisions per rule.

For each finding, determine its classification and a recommended action:

| Classification | Confidence | Criteria | Recommended action |
|---|---|---|---|
| **True positive — fixable** | — | Real issue, fix is straightforward | Fix in code (auto-resolves after merge) |
| **True positive — complex** | — | Real issue, fix requires significant effort | `in_progress` or `dismiss_no_capacity` |
| **False positive** (high confidence) | **High** | You are certain the scanner is wrong — clear evidence in code | Dismiss (`dismiss_not_accurate`) |
| **False positive** (medium/low confidence) | **Med/Low** | Likely or possibly a false positive but not certain | **Keep as-is** — do NOT recommend dismissal |
| **Accept risk** (high confidence) | **High** | True positive, but **low risk** AND **high fix complexity** — the cost of fixing clearly outweighs the risk | Accept (`risk_accepted`) |
| **Accept risk** (medium/low confidence) | **Med/Low** | Might be acceptable but not sure about risk level or fix scope | **Keep as-is** — do NOT recommend acceptance |

**CRITICAL: Err on the side of caution.** Only recommend dismissing or accepting
risk when you have **high confidence** in the verdict. If there is any doubt,
recommend leaving the finding in its current state. Accidentally dismissing or
accepting a real, exploitable vulnerability is far worse than leaving a false
positive or low-risk finding open for human review.

**High-confidence false positive** indicators:
- The flagged code is clearly in a test file / test-only path
- The scanner rule explicitly does not apply (e.g. the language/framework
  handles the concern automatically)
- The flagged pattern is a well-known false positive for this specific rule
- The code is dead / unreachable and you can prove it

**High-confidence risk acceptance** indicators (ALL must apply):
- The finding is a real true positive (not a false positive)
- The **risk is low** (e.g. no user input reaches the vulnerable code, the
  affected component is internal-only, or the exploitability is theoretical)
- The **fix complexity is high** (significant refactoring, breaking changes,
  or cross-cutting concerns)
- You can clearly articulate why the risk is acceptable

**Medium/low confidence — do NOT recommend dismissal or acceptance** when:
- You think it's probably fine but can't point to definitive proof
- The code is complex and you're not certain about the execution context
- The vulnerability depends on runtime configuration you can't verify
- The finding is about a dependency and you're unsure about transitive usage
- You're unsure whether the risk is truly low or the fix is truly complex

Present findings as a triage table:

```
| # | File | Line | Finding | Verdict | Confidence | Effort | Risk | Recommendation |
|---|------|------|---------|---------|------------|--------|------|----------------|
```

After the table, include detailed reasoning for each classification,
**especially explaining the confidence level for each false positive verdict**.

Common false positive patterns by category:

**SAST:**
- `unsafe` FFI in zero-dependency Rust projects (required for OS API calls)
- `std::env::temp_dir()` in test-only code paths
- `std::env::args()` in CLI entry points

**SCA (vulnerable dependencies):**
- CVE in a transitive dependency that is never actually invoked
- Vulnerability in a dev-only dependency not shipped to production
- CVE already mitigated by the application's usage pattern

**SCA reachability analysis:** For SCA findings, check the `reachability` field
in the API response — it may indicate whether the vulnerable code path is
actually reachable. If `reachability` is null or absent, assess reachability
manually by examining how the vulnerable package/component is used in the code:
- Is it a CLI tool run as a child process? (CVEs in its internal libraries
  may not be reachable)
- Is it a build-time-only dependency? (not in runtime image)
- Does the CVE require a specific usage pattern (e.g. gRPC server, SSH
  connections) that the app doesn't use?
- Is it a runtime dependency that processes untrusted input? (likely reachable)

Include reachability reasoning in the triage table for every SCA finding.

**IaC / CI/CD:**
- `curl | sh` flagged on legitimate installer scripts (though often a TP)
- Overly broad permissions in a workflow that only runs on manual trigger
- S3 bucket "public access" that is intentionally a static website

---

### GATE 1 — User approves what to fix

**STOP. Do not make any code changes yet.** Present the user with a structured
choice using the AskQuestion tool.

**Include batch context in the question itself** so the user doesn't have to
scroll up to the triage table. The question prompt should summarize:
- What batch this is (severity + type)
- Total findings in the batch
- How many are true positives vs false positives vs risk-accepted
- A one-line summary of each true positive being proposed for fixing

Example question prompt:
> **Critical SAST findings (6 total): 1 true positive, 5 false positives.**
> The true positive is: #4 JWT_NO_VERIFY auth bypass in `src/auth/middleware.ts:42`
> (effort: low, risk: high). Should we fix it?

Options:
- **Fix #4** (or list specific findings) — fix the recommended true positive(s)
- **Fix all true positives** — fix every true positive regardless of effort
- **Skip fixes for this batch** — make no code changes

Wait for the user's answer before proceeding.

---

### Step 4: Fix approved true positives

Apply code fixes only for findings the user approved.

**Always check `details.recommendation` first** — when present, the scanner
provides a remediation hint that's tailored to the specific finding (often
including a code diff or version pin). Prefer it over the generic patterns
below. Fall back to the patterns only when `details.recommendation` is absent
or unhelpful.

Common fix patterns:

**SAST:**

| Finding | Fix |
|---|---|
| SQL injection / unsanitized input | Use parameterized queries or input validation |
| Missing SRI on `<script src="...">` | Add `integrity="sha384-..."` and `crossorigin="anonymous"` |
| Insecure random number generation | Replace `Math.random()` with `crypto.randomBytes()` |

**SCA (vulnerable dependencies):**

| Finding | Fix |
|---|---|
| CVE in a direct dependency | Upgrade to the patched version in `package.json` / `requirements.txt` / etc. |
| CVE in a transitive dependency | Add a resolution/override to pin the safe version |

**IaC / CI/CD:**

| Finding | Fix |
|---|---|
| `curl \| sh` in CI workflows | Replace with official pinned GitHub Actions |
| Excessive workflow permissions | Narrow `permissions:` to least privilege per job |
| IaC misconfiguration (e.g. open security group) | Tighten the resource policy to least privilege |

### Step 5: Verify fixes

Run the project's build and test suite.

**Inferring the build/test command** (in priority order):
1. `package.json` `scripts` (`npm test`, `npm run build`, `pnpm test`, etc.)
2. `pyproject.toml` / `tox.ini` / `pytest.ini` → `pytest` or `tox`
3. `Cargo.toml` → `cargo build && cargo test`
4. `go.mod` → `go build ./... && go test ./...`
5. `Makefile` targets named `test`, `check`, `build`
6. `README.md` "Development" / "Testing" section
7. CI config (`.github/workflows/*.yml`, `.gitlab-ci.yml`) — copy the test step
8. If you can't determine the command in <30 seconds: **ask the user once**
   what to run; don't guess and don't skip verification silently.

If tests or build fail:
- **Failures caused by your fix:** Undo or correct the fix before proceeding.
- **Pre-existing failures** (unrelated to your changes): Note them in the
  triage output and proceed. Do not block the triage workflow on build issues
  that existed before your changes.

---

### GATE 2 — User approves what to dismiss/update

**STOP. Do not call the Arnica API yet.** Present the user with a structured
choice using the AskQuestion tool.

Show findings in **three separate groups**:

**Group A — Recommended for dismissal** (high-confidence false positives):
Only findings where you are certain the scanner is wrong. Show the proposed
status (`dismiss_not_accurate`), reason, and your confidence justification.

**Group B — Recommended for risk acceptance** (high-confidence low-risk):
True positives where the risk is clearly low and the fix complexity is clearly
high. Show the proposed status (`risk_accepted`), reason, and why the risk/effort
trade-off justifies acceptance.

**Group C — Recommended to keep as-is:**
Everything else — medium/low confidence false positives, findings where you're
unsure about the risk level, and anything you're not certain about. Explain why
each one should be left for human review.

**Include batch context in the question** so the user has the full picture
without scrolling. Summarize the group counts and list specific findings.

Example question prompt:
> **Critical SAST — 5 remaining findings after fixes:**
> Group A (dismiss as false positive, 4 findings): #1 temp_dir in test,
> #2 unsafe FFI, #3 args() in CLI, #6 dead code path.
> Group B (accept risk, 0 findings): none.
> Group C (keep for review, 1 finding): #5 unvalidated input — medium
> confidence, leaving for human review.

Options:
- **Dismiss & accept as recommended** — dismiss Group A (4) as false positives,
  accept risk for Group B (0), leave Group C (1) for human review
- **Dismiss only** — dismiss Group A (4) only, leave Groups B and C as-is
- **Let me pick individually** — present each Group A/B finding as its own
  yes/no question (use this when the user wants surgical control over a large
  batch). Issue the per-finding follow-ups, then proceed to Step 6 with only
  the approved subset.
- **Do nothing** — leave all 5 findings in their current state

**Never recommend bulk-dismissing or accepting findings you're not certain
about.** It is far better to leave a finding open for human review than to
accidentally dismiss or accept a real, exploitable vulnerability.

Wait for the user's answer before proceeding.

---

### Step 6: Dismiss/update approved findings via API

Only if the user approved in Gate 2. Use `PUT /v1/risks/{id}/status` —
endpoint syntax, URL-encoding rules for the finding `id`, and the full status
enums are documented in the `arnica-api` skill. Stick to the writable statuses
listed under "Dismiss/update statuses (workflow-allowed subset)" above.

**Concurrency**: issue PUTs serially or with small parallelism (≤5 in-flight)
to avoid `429`. On `429`, back off with exponential delay + jitter (start at
1s, double on each retry, max 30s, cap at 5 retries). The `arnica-api` skill
has the full backoff guidance.

**Partial failures**: a successful PUT returns HTTP 204; anything else (400 /
403 / 404 / 5xx) means the update did NOT take effect. Track outcomes per
finding ID:

| Result | Action |
|---|---|
| `204` | Mark as updated, continue |
| `403 message="…required scopes…"` | Stop the batch — token is missing `risks:write`. Surface to user. |
| `403 message="Forbidden"` | Token invalid/expired. Stop and surface. |
| `404` | Finding may have been resolved/deleted between fetch and update. Note and continue. |
| `429` | Back off and retry per above. After 5 retries, fail this ID and continue. |
| `5xx` | Retry once after 2s. If still failing, note and continue. |

After the batch, **always print a partial-failure summary** if any PUTs failed
non-204, listing the finding IDs and the error message — even if the rest
succeeded. Don't move on to the next batch until the user has seen the
failures.

**Rollback**: if the user realizes a dismissal was wrong, PUT `requires_review`
on that finding ID — it returns to the triage queue.

**Reason guidelines:**
- Always explain WHY, not just WHAT the code does
- Reference the project's design constraints if relevant
- Mention if the code is test-only (never compiled into release binary)
- For batch dismissals of the same rule, use a consistent reason template

### Step 7: Verify batch results

Query the API again for this severity + type to confirm status changes took
effect.

**Eventual consistency**: status updates may take a few seconds to propagate.
If a re-fetch still shows updated findings as `requires_review`, wait ~5
seconds and try once more before flagging it as a real failure. If it still
hasn't propagated, surface this to the user (don't loop indefinitely).

Present a brief summary (per Step 6's outcome table), then announce the next
batch and continue the loop.

---

## After all batches

### Step 8: Final summary

Present a summary table across all batches:

```
| Severity | Type | Total | Fixed | Dismissed | Accepted | Remaining |
|----------|------|-------|-------|-----------|----------|-----------|
| critical | SAST |   ... |   ... |       ... |      ... |       ... |
| critical | SCA  |   ... |   ... |       ... |      ... |       ... |
| ...      | ...  |   ... |   ... |       ... |      ... |       ... |
```

Include totals at the bottom.
