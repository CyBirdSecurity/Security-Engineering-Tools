## ⚠️ Isolated fix — major/breaking upgrade for a [CRITICAL|HIGH] severity vulnerability

This PR is **not** part of a bulk batch. It upgrades **[package_name]** across a **major** version boundary (or a version with a known/likely breaking change) because the vulnerability it fixes is severity **[CRITICAL|HIGH]** and no smaller-risk fix is available. It was opened automatically but requires **manual review before merge** — do not fast-track it the way you would a bulk patch/minor PR.

## Vulnerability details

| Field | Value |
|---|---|
| Package | [package_name] ([ecosystem]) |
| Current version | [current_version] |
| Patched version | [first_patched_version] |
| Severity | [severity] (CVSS [cvss_score if available]) |
| Advisory | [GHSA-xxxx](url) / [CVE-xxxx-xxxxx] |
| Manifest | [manifest_path] |
| Scope | [direct/runtime \| transitive/development] |

**Summary:** [advisory summary text]

## Why this couldn't be bundled into a bulk PR

The jump from `[current_version]` to `[first_patched_version]` crosses a major version boundary (or otherwise carries a documented breaking change), which means:
- semver does not guarantee backwards compatibility
- [note any specific breaking changes found in the package's changelog/release notes, or state "changelog was not checked / not available — treat compatibility as unverified"]

Given the [CRITICAL|HIGH] severity, the risk of leaving this vulnerable dependency in place was judged to outweigh the risk of a breaking upgrade — but that tradeoff should be confirmed by a human reviewer, not merged on the strength of this description alone.

## Testing performed

- [ ] Dependency install completed cleanly (`[install command used]`)
- [ ] Project build succeeded (`[build command used, or "N/A"]`)
- [ ] Existing test suite run: `[test command used]` — **[N passed / N failed / no test suite detected]**
- [ ] [Any manual smoke-test performed against the package's changed API surface, if applicable]

**What still needs manual verification:** [call out anything the automated pass could not exercise — e.g. code paths not covered by tests, config options the package renamed, etc.]

## Rollback plan

If this causes issues post-merge: revert this single commit/PR — it is isolated from all other dependency changes in this remediation run, so reverting it will not affect the bulk patch/minor PRs.

## Reviewer checklist

- [ ] Read the package's changelog/release notes for the version range crossed
- [ ] Confirm CI is green
- [ ] Confirm the "what still needs manual verification" items above have been checked or are acceptable to ship without
- [ ] This PR requires an explicit human approval — it is not eligible for any auto-merge policy
