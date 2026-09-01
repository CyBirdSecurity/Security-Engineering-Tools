#!/usr/bin/env python3
"""
Pull open Dependabot alerts for a repo via the GitHub CLI and normalize them
to a flat JSON list that classify_risk.py can consume.

Requires: `gh` CLI, authenticated, with access to the target repo.

Usage:
    python3 fetch_alerts.py --repo owner/name --out alerts.json
    python3 fetch_alerts.py --out alerts.json   # infers owner/repo from the
                                                 # current git remote via `gh`
"""
import argparse
import json
import subprocess
import sys


def run_gh(args):
    result = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, check=False
    )
    return result


def resolve_repo(explicit):
    if explicit:
        return explicit
    result = run_gh(["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"])
    if result.returncode != 0:
        sys.exit(
            "ERROR: could not determine owner/repo automatically. "
            "Pass --repo owner/name explicitly.\n" + result.stderr
        )
    return result.stdout.strip()


def fetch_page(repo, state, page, per_page):
    endpoint = f"/repos/{repo}/dependabot/alerts"
    result = run_gh(
        [
            "api",
            "-X", "GET",
            endpoint,
            "-f", f"state={state}",
            "-f", f"per_page={per_page}",
            "-f", f"page={page}",
        ]
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "404" in stderr:
            sys.exit(
                "ERROR: 404 from Dependabot alerts API. Either Dependabot "
                "alerts are not enabled for this repo (Settings > Code "
                "security), or the authenticated `gh` account lacks access.\n"
                + stderr
            )
        if "403" in stderr:
            sys.exit(
                "ERROR: 403 from Dependabot alerts API. The authenticated "
                "`gh` token needs read access to security alerts "
                "(repo admin/security-events scope, or org policy).\n"
                + stderr
            )
        sys.exit(f"ERROR calling gh api: {stderr}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        sys.exit(f"ERROR: could not parse gh api response as JSON: {exc}")


def normalize(alert):
    advisory = alert.get("security_advisory") or {}
    vuln = alert.get("security_vulnerability") or {}
    dependency = alert.get("dependency") or {}
    package = dependency.get("package") or {}
    patched = vuln.get("first_patched_version") or {}
    cvss = advisory.get("cvss") or {}

    return {
        "number": alert.get("number"),
        "state": alert.get("state"),
        "severity": (advisory.get("severity") or "").lower(),
        "cvss_score": cvss.get("score"),
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "summary": advisory.get("summary"),
        "references": [r.get("url") for r in advisory.get("references", []) if r.get("url")],
        "package_name": package.get("name"),
        "ecosystem": package.get("ecosystem"),
        "manifest_path": dependency.get("manifest_path"),
        "scope": dependency.get("scope"),
        "vulnerable_version_range": vuln.get("vulnerable_version_range"),
        "first_patched_version": patched.get("identifier"),
        "url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="owner/name, inferred via `gh repo view` if omitted")
    parser.add_argument("--state", default="open", choices=["open", "fixed", "dismissed", "auto_dismissed"])
    parser.add_argument("--out", default="alerts.json", help="output JSON file path")
    parser.add_argument("--per-page", type=int, default=100)
    args = parser.parse_args()

    repo = resolve_repo(args.repo)

    all_alerts = []
    page = 1
    while True:
        batch = fetch_page(repo, args.state, page, args.per_page)
        if not batch:
            break
        all_alerts.extend(batch)
        if len(batch) < args.per_page:
            break
        page += 1

    normalized = [normalize(a) for a in all_alerts]

    with open(args.out, "w") as f:
        json.dump(normalized, f, indent=2)

    by_severity = {}
    for a in normalized:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1

    print(f"Repo: {repo}", file=sys.stderr)
    print(f"Fetched {len(normalized)} '{args.state}' Dependabot alert(s) -> {args.out}", file=sys.stderr)
    for sev in ("critical", "high", "medium", "low"):
        if sev in by_severity:
            print(f"  {sev}: {by_severity[sev]}", file=sys.stderr)


if __name__ == "__main__":
    main()
