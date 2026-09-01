# Security Engineering Tools

A collection of tools, GitHub Actions, and configuration guides for
automating security engineering work — mainly dependency vulnerability
remediation and repo hardening. Each item lives in its own folder below and
is meant to be copied/adapted into your own repo(s) rather than used as-is;
review the comments and configuration notes in each file before deploying.

## What's in here

### `Claude Plugins/security-bundler/`
A [Claude Code](https://claude.com/product/claude-code) plugin that triages a
repo's open GitHub Dependabot alerts: it bundles low-risk (patch/minor)
upgrades into a handful of reviewable PRs, opens flagged isolated PRs for
critical/high severity issues that need a riskier major-version bump, and
writes up everything it couldn't safely automate for a human to plan. It
never merges, approves, or pushes to a default branch on its own — see the
plugin's own [README](Claude%20Plugins/security-bundler/README.md) for
prerequisites and usage.

### `Github Actions/Security-Dependency-Auto-Patch.yml`
A GitHub Actions workflow that auto-approves and auto-merges Dependabot PRs
once they clear a configurable compatibility-score threshold, using a
dedicated service account/PAT. This trades human review for throughput on
low-risk bumps — read
[`Security-Dependency-Auto-Patch.md`](Github%20Actions/Security-Dependency-Auto-Patch.md)
for the setup steps (label, auto-merge setting, service account) and make
sure that tradeoff is right for your repo before enabling it. Third-party
actions are pinned to a commit SHA to reduce supply-chain risk; if you bump
a version, re-pin to the new SHA rather than a mutable tag.

### `Github Secure Configurations/PR_Review.md`
A short guide for enforcing PR review requirements org-wide using GitHub
repository rulesets, plus a pattern for tagging specific repos as exceptions
(e.g. compliance scope) without giving every repo owner the ability to
disable the rule themselves.

## Using these tools

Nothing here is a turnkey install — most items are templates or examples
that reference your own default branch, org policies, and secrets. Before
using anything in this repo:

- Read the comments in the file you're adopting; they call out what to
  change for your environment (branch names, compatibility thresholds,
  label names, etc.).
- Any workflow that grants `contents: write` / `pull-requests: write` and
  merges automatically (like the auto-patch Action) should use a
  least-privilege service account/PAT scoped only to what it needs, and you
  should understand what it will merge without a human in the loop before
  turning it on.
- Treat everything here as a starting point to adapt, not a drop-in
  dependency.

## License

[MIT](LICENSE)

## Questions

Feel free to reach out with any questions: dklauser@cybirdsecurity.com
