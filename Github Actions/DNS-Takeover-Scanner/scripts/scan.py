#!/usr/bin/env python3
"""DNS takeover scan: discover subdomains from Certificate Transparency, check
each for dangling CNAME / NS / MX / SPF records, and reconcile GitHub issues.

Configuration (environment):
  DNS_ROOT_DOMAINS      required; domains you own, comma/space/newline separated
  DNS_RESOLVERS         recursive resolvers (default 1.1.1.1,8.8.8.8)
  CERTSPOTTER_API_KEY   optional; raises Cert Spotter's quota
  DNS_MAX_WORKERS       parallel host checks (default 16)
  FAIL_ON               high | medium | none - fail the run when findings at this
                        severity or above exist (default high)
  DRY_RUN               "true" = report only, don't touch issues
  ALLOW_PUBLIC_REPO     "true" = allow issues in a public repo (not recommended)
  GITHUB_TOKEN, GITHUB_REPOSITORY   issue reporting (set by Actions)
"""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import sys

import checks
import ct
import dnslite as d
import issues

INCONCLUSIVE_LIMIT = 0.2  # more than 20% of hosts unchecked = scan problem


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    print(md)


def run_url() -> str:
    repo, run = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_RUN_ID")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/actions/runs/{run}" if repo and run else "(local run)"


def root_of(host: str, roots: list[str]) -> str:
    return max((r for r in roots if host == r or host.endswith("." + r)), key=len)


def main() -> int:
    roots = sorted({d.normalize(r) for r in re.split(r"[,\s]+", env("DNS_ROOT_DOMAINS")) if r.strip()})
    if not roots:
        print("::error::Set DNS_ROOT_DOMAINS (repository variable) to the domains to scan.")
        return 1
    resolvers = [s for s in re.split(r"[,\s]+", env("DNS_RESOLVERS", "1.1.1.1,8.8.8.8")) if s]
    dry_run = env("DRY_RUN").lower() == "true"
    fail_on = env("FAIL_ON", "high").lower()
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    gh = None
    if not dry_run:
        token, repo = env("GITHUB_TOKEN"), env("GITHUB_REPOSITORY")
        if not token or not repo:
            print("::error::GITHUB_TOKEN/GITHUB_REPOSITORY missing; set DRY_RUN=true to scan without issues.")
            return 1
        gh = issues.GitHub(token, repo, env("GITHUB_API_URL", "https://api.github.com"))
        # Findings are a map of how to hijack your domains: keep them private.
        if not gh.repo_is_private() and env("ALLOW_PUBLIC_REPO").lower() != "true":
            print("::error::This repository is public. Findings would be published in issues and logs. "
                  "Run the scanner from a private repository.")
            return 1

    # ---- discovery ----------------------------------------------------------
    by_root, warnings, failed_roots = ct.discover(roots, env("CERTSPOTTER_API_KEY") or None)
    hosts = sorted({h for names in by_root.values() for h in names})
    print(f"{len(hosts)} hostnames from Certificate Transparency across {len(roots)} root domain(s).")

    res = d.Resolver(resolvers)
    psl = checks.PublicSuffixList.download()
    fps = checks.load_fingerprints()

    # ---- CNAME + mail checks (parallel) ---------------------------------------
    results: dict[str, list[checks.HostResult]] = {h: [] for h in hosts}
    with cf.ThreadPoolExecutor(max_workers=int(env("DNS_MAX_WORKERS", "16"))) as pool:
        futures = {}
        for h in hosts:
            futures[pool.submit(checks.check_cname, res, psl, fps, h)] = h
            futures[pool.submit(checks.check_mail, res, psl, h)] = h
        for fut in cf.as_completed(futures):
            h = futures[fut]
            try:
                results[h].append(fut.result())
            except Exception as e:  # noqa: BLE001 - one host must not stop the scan
                results[h].append(checks.HostResult(h, checked=False, errors=[f"{type(e).__name__}: {e}"]))

    # ---- NS delegation walk (sequential: shares one cache per zone) -----------
    deleg = checks.DelegationChecker(res, psl, fps)
    deleg_findings: dict[str, list[checks.Finding]] = {}
    deleg_ok: dict[str, bool] = {}
    for h in hosts:
        before = len(deleg.errors)
        try:
            deleg_findings[h] = deleg.check_host(h, root_of(h, roots))
            deleg_ok[h] = len(deleg.errors) == before
        except Exception as e:  # noqa: BLE001
            deleg_findings[h], deleg_ok[h] = [], False
            deleg.errors.append(f"{h}: {type(e).__name__}: {e}")

    # ---- collect ---------------------------------------------------------------
    findings: dict[str, dict] = {}
    rechecked: set[str] = set()
    inconclusive: list[str] = []
    for h in hosts:
        hrs = results[h]
        for hr in hrs:
            for f in hr.findings:
                findings[f.id] = f.to_dict()
        for f in deleg_findings.get(h, []):
            findings[f.id] = f.to_dict()
        if all(hr.checked for hr in hrs) and deleg_ok.get(h, False):
            rechecked.add(h)
        else:
            inconclusive.append(h)
    # Delegation findings are keyed by the delegated zone name, which may not
    # itself appear in CT; count it as re-checked when the walk was clean.
    for h in hosts:
        if deleg_ok.get(h):
            for anc in checks.ancestors(h, root_of(h, roots)):
                rechecked.add(anc)

    problems: list[str] = [f"No Certificate Transparency source worked for `{r}`; its subdomains were "
                           "not scanned." for r in sorted(failed_roots)]
    if hosts and len(inconclusive) / len(hosts) > INCONCLUSIVE_LIMIT:
        problems.append(f"{len(inconclusive)} of {len(hosts)} hosts couldn't be fully checked (DNS errors). "
                        "Their open issues were left as they are.")

    with open("findings.json", "w", encoding="utf-8") as fh:
        json.dump({"scanned_at": now, "roots": roots, "hosts": len(hosts), "findings": list(findings.values()),
                   "inconclusive_hosts": inconclusive, "warnings": warnings + deleg.errors[:200],
                   "problems": problems}, fh, indent=2)

    # ---- issues ------------------------------------------------------------------
    counts = {}
    if gh:
        for sev, color in (("high", "b60205"), ("medium", "fbca04")):
            gh.ensure_label(f"{issues.LABEL}:{sev}", color, f"DNS takeover finding ({sev})")
        gh.ensure_label(issues.LABEL, "d93f0b", "Possible subdomain / DNS takeover")
        actions = issues.plan_actions(findings, gh.issues(issues.LABEL), rechecked)
        counts = issues.apply_actions(gh, actions, now, run_url())

    # ---- summary -----------------------------------------------------------------
    by_sev = {"high": 0, "medium": 0}
    for f in findings.values():
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    lines = [f"### DNS takeover scan — {now}", "",
             f"Roots: {', '.join(f'`{r}`' for r in roots)} · hostnames: {len(hosts)} · "
             f"inconclusive: {len(inconclusive)}", "",
             "| Severity | Findings |", "|---|---|", f"| high | {by_sev['high']} |", f"| medium | {by_sev['medium']} |"]
    if findings:
        lines += ["", "| Severity | Host | Type | Target |", "|---|---|---|---|"]
        for f in sorted(findings.values(), key=lambda f: (f["severity"] != "high", f["host"])):
            lines.append(f"| {f['severity']} | `{f['host']}` | {f['type']} | `{f['target']}` |")
    if counts:
        lines += ["", "Issues: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))]
    if problems:
        lines += ["", "#### Problems"] + [f"- {p}" for p in problems]
    if warnings:
        lines += ["", "#### Warnings"] + [f"- {w}" for w in warnings[:20]]
    summary("\n".join(lines))

    if gh:
        issues.report_scan_failure(gh, bool(problems), "\n".join(lines) + f"\n\nRun: {run_url()}")

    if problems:
        return 1
    threshold = {"high": ["high"], "medium": ["high", "medium"]}.get(fail_on, [])
    return 1 if any(f["severity"] in threshold for f in findings.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
