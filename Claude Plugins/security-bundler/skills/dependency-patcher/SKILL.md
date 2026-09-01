---
name: dependency-patcher
description: Use when asked to remediate, triage, patch, or bulk-upgrade dependency vulnerabilities / Dependabot alerts for a GitHub repo, or when invoked as /security-bundler:dependency-patcher. Pulls open Dependabot alerts via the GitHub CLI, classifies fixes by upgrade risk and severity, opens grouped bulk PRs for low-risk upgrades and flagged isolated PRs for critical/high severity issues needing risky upgrades, and writes a triage report for everything else.
---

# Dependency Patcher

You are running a security remediation pass against the current repository's
open GitHub Dependabot alerts. The goal is **leverage**: close as many
vulnerabilities as possible with the least reviewer burden, by separating
"safe to bundle" upgrades from "needs a human's judgment" upgrades, and by
weighting effort toward critical/high severity findings.

This skill has two helper scripts (deterministic, no LLM guessing on version
math) and three PR/report templates in this skill's own directory:

```
${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/scripts/fetch_alerts.py
${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/scripts/classify_risk.py
${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/templates/pr_bulk_template.md
${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/templates/pr_isolated_template.md
${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/templates/triage_report_template.md
```

Use the scripts for fetching/classifying — do not hand-compute semver diffs
yourself. Use the templates as the starting body for every PR and for the
final report; fill in the bracketed placeholders, don't invent a different
structure.

## Safety rules (non-negotiable)

- Never commit or push directly to the repo's default branch. Every change
  goes on a dedicated branch and through a PR.
- Never merge or approve a PR yourself, and never add an auto-merge label.
  This skill's job ends at "PR opened, ready for review." Merge policy is the
  repo owner's decision.
- Never bundle a major/breaking upgrade into a bulk PR. Bulk PRs are
  patch-only or minor-only, never mixed with major bumps.
- Before starting, run `git status`. If the working tree isn't clean, stop
  and tell the user rather than working on top of uncommitted changes.
- Work off the repo's actual default branch (`gh repo view --json
  defaultBranchRef`), not an assumed `main`.

## Step 0 — Preflight

1. Confirm `gh auth status` is authenticated. If not, stop and tell the user.
2. Confirm the repo has Dependabot alerts enabled by attempting the fetch in
   Step 1 — a clean 404 means it's off; report that to the user and stop.
3. `git status` clean check per Safety rules above.
4. Note the default branch name for later branch/PR creation.

## Step 1 — Fetch open alerts

```
python3 "${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/scripts/fetch_alerts.py" --out alerts.json
```

This writes a normalized JSON list (severity, GHSA/CVE id, package,
ecosystem, manifest path, vulnerable range, first patched version, URL) and
prints a severity breakdown to stderr. If it exits non-zero, read its error
message (it explains 404s/403s clearly) and relay that to the user instead
of guessing.

If there are zero open alerts, tell the user the repo is clean and stop —
no need to continue.

## Step 2 — Determine currently-installed versions

`classify_risk.py` needs to know what version of each flagged package is
*actually* installed right now (the Dependabot alert only gives you the
vulnerable range and the first patched version, not the pinned version).

For every distinct `(ecosystem, package_name, manifest_path)` in
`alerts.json`, read the relevant manifest/lockfile in the repo and record the
resolved version. Typical sources by ecosystem:

- **npm/yarn/pnpm**: `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
  (prefer the lockfile over `package.json`'s range for the *actual* resolved
  version)
- **pip/Poetry/Pipenv**: `poetry.lock`, `Pipfile.lock`, or a pinned line in
  `requirements*.txt`
- **Go modules**: `go.sum` / `go.mod`
- **Maven**: resolved version in `pom.xml` or via `mvn dependency:tree` if
  the version comes from a parent/BOM
- **Gradle**: `build.gradle(.kts)` or the lockfile if one exists
- **RubyGems**: `Gemfile.lock`
- **NuGet**: `packages.lock.json` or the `.csproj` PackageReference version

Write these into `installed_versions.json`, keyed as
`"<ecosystem>::<package_name>::<manifest_path>"` (fall back to
`"<ecosystem>::<package_name>"` for single-manifest repos):

```json
{
  "npm::lodash::package.json": "4.17.19",
  "pip::requests::requirements.txt": "2.25.0"
}
```

If you genuinely cannot resolve a version for a package (e.g. it's not
actually present, or the lockfile format is unfamiliar), just omit it —
`classify_risk.py` will route it to `manual_review` automatically.

## Step 3 — Classify and group

```
python3 "${CLAUDE_PLUGIN_ROOT}/skills/dependency-patcher/scripts/classify_risk.py" \
  --alerts alerts.json \
  --installed-versions installed_versions.json \
  --out groups.json \
  --max-batch-size 18
```

This applies the decision matrix and writes `groups.json` with these
buckets:

| Bucket | Meaning | Action |
|---|---|---|
| `bulk_patch` | patch-only bump available | Bundle into batch PR(s), capped at 18/PR |
| `bulk_minor` | minor bump available, same major | Bundle into batch PR(s), capped at 18/PR, **separate PRs from bulk_patch** |
| `isolated_critical_high` | major/breaking bump, but severity is critical/high | **One PR per package**, heavily flagged, manual review required |
| `deferred_major_low_severity` | major/breaking bump, severity medium/low | **No PR** — not worth the breaking-change risk automatically. List in report. |
| `manual_review` | couldn't resolve installed version or version string isn't numeric semver | **No PR** — list in report |
| `no_fix_available` | Dependabot has no patched version yet | **No PR** — list in report as "monitor" |
| `no_action_needed` | installed version is already >= patched version | Skip silently |

This is where "weight toward critical and high severity" is actually
enforced: risky (major/breaking) upgrades only happen automatically when the
severity justifies the risk. Medium/low severity findings that would require
a breaking change are deliberately left for a human to plan, not force-bumped.

## Step 4 — Execute each bulk batch (`bulk_patch`, `bulk_minor`)

For each batch object in `groups.json` (process `bulk_patch` batches before
`bulk_minor`, and within a bucket process in the severity-sorted order the
script already gave you):

1. Branch off the default branch:
   `security/dep-bulk-<patch|minor>-<YYYYMMDD>-<batch-index>`
2. For each package in the batch, upgrade it to `first_patched_version`
   using the ecosystem's own tooling so the lockfile stays consistent —
   don't hand-edit lockfile entries:
   - npm: `npm install <pkg>@<version>`
   - yarn: `yarn add <pkg>@<version>`
   - pnpm: `pnpm add <pkg>@<version>`
   - pip: update the pin in the requirements file, then
     `pip install -r requirements.txt` / `poetry update <pkg>` / `pipenv update <pkg>`
   - Go: `go get <pkg>@<version>` then `go mod tidy`
   - Maven/Gradle/RubyGems/NuGet: use that ecosystem's own dependency-update
     command/file edit + lock regeneration
3. Install cleanly, build (if the repo has a build step), and run the
   repo's existing test suite (detect it: `package.json` `scripts.test`,
   `Makefile` `test` target, `tox.ini`/`pytest`, `go test ./...`,
   `mvn test`/`gradle test`, etc.).
4. **If a specific package's upgrade fails install/build/tests**: revert
   just that package's change, drop it from this batch, add it to a running
   "manual_review" list for the final report (reason: "local test/build
   failure"), and continue with the rest of the batch. Don't let one bad
   package block the other 17.
5. If the whole batch survives with at least one package, commit
   (`security: bulk <patch|minor> dependency upgrades (batch N of M)`), push,
   and open the PR:
   ```
   gh pr create --base <default-branch> --head <branch> \
     --title "security: bulk <patch|minor> dependency upgrades (batch N of M)" \
     --body-file <filled-in copy of pr_bulk_template.md>
   ```
   Fill the template's package table and testing checklist from what you
   actually did — don't leave placeholders in the published PR.
6. If every package in the batch failed, don't open an empty PR — delete the
   branch and record all of them under manual_review.

## Step 5 — Execute each isolated critical/high PR

For each entry in `isolated_critical_high` (one PR per package, potentially
resolving multiple alerts for that same package):

1. Branch: `security/dep-critical-<package-name>-<YYYYMMDD>`
2. Upgrade using the same ecosystem-appropriate commands as Step 4.
3. Before touching code, try to find the package's changelog/release notes
   for the version range crossed (check the repo's own vendored
   CHANGELOG, or `gh api` against the package's GitHub repo if you can
   identify it, or the ecosystem registry page) and summarize anything
   breaking you find. If you can't find one, say so explicitly in the PR —
   don't imply compatibility was verified when it wasn't.
4. Install, build, run the full existing test suite. Do **not** skip this
   step even though the alert is critical/high — a failing test here is
   exactly the signal this PR needs to surface, not hide.
5. Whether tests pass or not, still open the PR (severity justifies raising
   it even if it needs work) — but if tests fail, say so plainly in the
   testing section and consider marking the PR as a draft with
   `gh pr create --draft`.
6. Commit (`security: upgrade <package> to <version> (fixes <GHSA-id>, <severity>)`),
   push, and open the PR using `pr_isolated_template.md`, filled in
   completely — this template has more required detail than the bulk one
   (rollback plan, what still needs manual verification) because it's asking
   a human to accept breaking-change risk. Do not use `gh pr merge` or add
   any auto-merge label to this PR under any circumstances.

## Step 6 — Write the triage report

Fill in `triage_report_template.md` from `groups.json` plus the PR numbers
you actually created, and save it (e.g. `dependency-triage-report-<date>.md`
in the repo root or wherever the user prefers — ask if unclear). Then ask
the user whether they also want it filed as a GitHub issue
(`gh issue create --title "Dependency vulnerability triage — <date>" --body-file <report>`)
— don't create the issue without confirming, since it's a visible/shared
action.

## Step 7 — Summarize to the user

Report, in your own words (not just dumping the JSON): how many alerts were
found, how many PRs you opened and of what kind, how many were deferred and
why, and where the triage report lives. Link the PRs.
