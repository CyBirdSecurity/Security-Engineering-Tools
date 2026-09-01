# Dependency Vulnerability Triage Report

**Repo:** [owner/repo]
**Generated:** [ISO date/time]
**Run by:** security-bundler plugin's dependency-patcher skill

## Summary

| Bucket | Count | Outcome |
|---|---|---|
| Patch-level bulk upgrades | [N] alerts across [N] PR(s) | Opened |
| Minor-level bulk upgrades | [N] alerts across [N] PR(s) | Opened |
| Critical/High requiring major bump | [N] alerts across [N] PR(s) | Opened — isolated, flagged for manual review |
| Deferred (major bump, medium/low severity) | [N] alerts | **Not touched automatically** — see below |
| Manual review needed | [N] alerts | **Not touched automatically** — see below |
| No fix available yet | [N] alerts | Monitor — nothing to do yet |
| Already current / no action needed | [N] alerts | No action |

## PRs opened this run

| PR | Batch/Package | Alerts closed | Severity range |
|---|---|---|---|
| [#PR link] | [batch_id or package name] | [#alert, #alert, ...] | [e.g. medium-high] |

## Deferred: major/breaking bump required, severity did not justify an automatic risky upgrade

These need a human to decide whether the breaking upgrade is worth scheduling as planned work.

| Package | Ecosystem | Current → Patched | Severity | Advisory |
|---|---|---|---|---|
| [package_name] | [ecosystem] | [current] → [patched] | [medium\|low] | [GHSA/CVE link] |

## Manual review needed (could not classify automatically)

| Package | Ecosystem | Reason | Advisory |
|---|---|---|---|
| [package_name] | [ecosystem] | [no installed version found \| non-numeric version string \| local test failure pulled it from its batch] | [GHSA/CVE link] |

## No fix available yet (monitor)

| Package | Ecosystem | Severity | Advisory | Notes |
|---|---|---|---|---|
| [package_name] | [ecosystem] | [severity] | [GHSA/CVE link] | Re-run this skill periodically — Dependabot will populate `first_patched_version` once a fix is published. |

## Next run

Re-run `/security-bundler:dependency-patcher` after these PRs merge to pick up whatever's left, or on a recurring cadence (weekly/monthly) to keep the deferred/no-fix-available lists current.
