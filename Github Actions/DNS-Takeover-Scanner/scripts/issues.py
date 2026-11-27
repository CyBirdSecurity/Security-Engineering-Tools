"""One GitHub issue per finding, reconciled every run.

  new finding                         -> open an issue
  finding still present, issue open   -> refresh the issue body ("last seen")
  finding gone, host re-checked       -> comment + close as completed
  finding gone, host not re-checked   -> leave open (DNS errors, CT outage)
  finding back after being fixed      -> reopen with a comment
  issue closed as "not planned"       -> accepted risk: never reopened

Each issue carries a hidden marker with the finding id and host, so matching
doesn't depend on titles.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

LABEL = "dns-takeover"
FAILURE_LABEL = "dns-takeover-scan-failure"
MARKER_RX = re.compile(r"<!-- dns-takeover-id: ([0-9a-f]{16}) host: (\S+) -->")


# ---------------------------------------------------------------------------
# Pure planning logic (unit-tested)
# ---------------------------------------------------------------------------

def parse_marker(body: str | None) -> tuple[str, str] | None:
    m = MARKER_RX.search(body or "")
    return (m.group(1), m.group(2)) if m else None


def plan_actions(findings: dict[str, dict], issues: list[dict], rechecked_hosts: set[str]) -> list[tuple]:
    """Return [(action, finding_or_None, issue_or_None)] with action in
    create | update | reopen | close | suppressed | keep."""
    by_id: dict[str, dict] = {}
    for iss in issues:
        mk = parse_marker(iss.get("body"))
        if not mk:
            continue
        # Prefer an open issue if there are several for the same id.
        prev = by_id.get(mk[0])
        if prev is None or (prev["state"] != "open" and iss["state"] == "open"):
            by_id[mk[0]] = iss
    actions = []
    for fid, f in sorted(findings.items()):
        iss = by_id.get(fid)
        if iss is None:
            actions.append(("create", f, None))
        elif iss["state"] == "open":
            actions.append(("update", f, iss))
        elif iss.get("state_reason") == "not_planned":
            actions.append(("suppressed", f, iss))
        else:
            actions.append(("reopen", f, iss))
    for fid, iss in sorted(by_id.items()):
        if fid in findings or iss["state"] != "open":
            continue
        host = parse_marker(iss.get("body"))[1]
        actions.append(("close" if host in rechecked_hosts else "keep", None, iss))
    return actions


def issue_title(f: dict) -> str:
    sev = f["severity"].upper()
    return f"[{sev}] Possible takeover: {f['host']} ({f['type']})"[:250]


def issue_body(f: dict, first_seen: str, last_seen: str, run_url: str) -> str:
    rows = [("Severity", f["severity"]), ("Type", f"`{f['type']}`"), ("Host", f"`{f['host']}`"),
            ("Record", f"`{f['record']}`"), ("Dangling target", f"`{f['target']}`")]
    if f.get("service"):
        rows.append(("Service", f["service"]))
    rows += [("First seen", first_seen), ("Last seen", last_seen)]
    table = "\n".join(f"| {k} | {v} |" for k, v in rows)
    return (f"| | |\n|---|---|\n{table}\n\n"
            f"**What's wrong:** {f['evidence']}\n\n"
            f"**Fix:** {f['remediation']}\n\n"
            "Verify by hand before acting (for unregistered domains, check WHOIS/RDAP). "
            "This issue closes itself after a scan no longer finds the problem. "
            "If this is a false positive or an accepted risk, close it as **not planned** and it won't be reopened.\n\n"
            f"Latest scan: {run_url}\n\n"
            f"<!-- dns-takeover-id: {f['id']} host: {f['host']} -->")


FIRST_SEEN_RX = re.compile(r"\| First seen \| ([^|]+) \|")


# ---------------------------------------------------------------------------
# GitHub REST (standard library)
# ---------------------------------------------------------------------------

class GitHub:
    def __init__(self, token: str, repo: str, api: str = "https://api.github.com"):
        self.token, self.repo, self.api = token, repo, api.rstrip("/")

    def call(self, method: str, path: str, body=None, params=None):
        url = path if path.startswith("http") else f"{self.api}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        safe_to_retry = method in ("GET", "PATCH")  # never repeat a POST that may have gone through
        for attempt in range(5):
            req = urllib.request.Request(url, data=data, method=method, headers={
                "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "dns-takeover-scanner",
                **({"Content-Type": "application/json"} if data else {})})
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw = r.read()
                    return (json.loads(raw) if raw else None), r.headers
            except urllib.error.HTTPError as e:
                if e.code == 404 and method == "GET":
                    return None, e.headers
                limited = e.code in (403, 429) and (e.headers.get("retry-after")
                                                    or e.headers.get("x-ratelimit-remaining") == "0")
                if limited:
                    wait = int(e.headers.get("retry-after") or
                               max(5, int(e.headers.get("x-ratelimit-reset", time.time() + 60)) - time.time()))
                    time.sleep(min(wait, 900))
                    continue
                if e.code >= 500 and safe_to_retry:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"GitHub API {method} {path}: HTTP {e.code} {e.read()[:300]!r}") from None
            except (urllib.error.URLError, TimeoutError) as e:
                if not safe_to_retry:
                    raise RuntimeError(f"GitHub API {method} {path}: {e}") from None
                time.sleep(2 ** attempt)
        raise RuntimeError(f"GitHub API {method} {path}: gave up")

    def repo_is_private(self) -> bool:
        data, _ = self.call("GET", f"/repos/{self.repo}")
        return bool(data and data.get("private"))

    def ensure_label(self, name: str, color: str, desc: str) -> None:
        found, _ = self.call("GET", f"/repos/{self.repo}/labels/{urllib.parse.quote(name)}")
        if not found:
            self.call("POST", f"/repos/{self.repo}/labels", {"name": name, "color": color, "description": desc})

    def issues(self, label: str, state: str = "all") -> list[dict]:
        out, url = [], f"{self.api}/repos/{self.repo}/issues?" + urllib.parse.urlencode(
            {"labels": label, "state": state, "per_page": 100})
        while url:
            page, headers = self.call("GET", url)
            out += [i for i in (page or []) if "pull_request" not in i]
            m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("link", "") if headers else "")
            url = m.group(1) if m else None
        return out


def apply_actions(gh: GitHub, actions: list[tuple], now: str, run_url: str, log=print) -> dict:
    counts: dict[str, int] = {}
    for action, f, iss in actions:
        counts[action] = counts.get(action, 0) + 1
        if action == "create":
            gh.call("POST", f"/repos/{gh.repo}/issues", {
                "title": issue_title(f), "body": issue_body(f, now, now, run_url),
                "labels": [LABEL, f"{LABEL}:{f['severity']}"]})
            log(f"opened issue for {f['host']} ({f['type']})")
        elif action in ("update", "reopen"):
            m = FIRST_SEEN_RX.search(iss.get("body") or "")
            first = m.group(1).strip() if m else now
            patch = {"title": issue_title(f), "body": issue_body(f, first, now, run_url)}
            if action == "reopen":
                patch["state"] = "open"
            gh.call("PATCH", f"/repos/{gh.repo}/issues/{iss['number']}", patch)
            if action == "reopen":
                gh.call("POST", f"/repos/{gh.repo}/issues/{iss['number']}/comments",
                        {"body": f"Reopened: the problem is back.\n\n{run_url}"})
                log(f"reopened #{iss['number']}")
        elif action == "close":
            gh.call("POST", f"/repos/{gh.repo}/issues/{iss['number']}/comments",
                    {"body": f"Resolved: the latest scan no longer finds this.\n\n{run_url}"})
            gh.call("PATCH", f"/repos/{gh.repo}/issues/{iss['number']}",
                    {"state": "closed", "state_reason": "completed"})
            log(f"closed #{iss['number']} (fixed)")
    return counts


def report_scan_failure(gh: GitHub, failed: bool, body: str) -> None:
    open_issues = gh.issues(FAILURE_LABEL, "open")
    if failed:
        gh.ensure_label(FAILURE_LABEL, "b60205", "DNS takeover scan could not run completely")
        if open_issues:
            gh.call("POST", f"/repos/{gh.repo}/issues/{open_issues[0]['number']}/comments", {"body": body})
        else:
            gh.call("POST", f"/repos/{gh.repo}/issues",
                    {"title": "DNS takeover scan failing", "body": body, "labels": [FAILURE_LABEL]})
    else:
        for iss in open_issues:
            gh.call("POST", f"/repos/{gh.repo}/issues/{iss['number']}/comments",
                    {"body": "Resolved: the latest scan completed."})
            gh.call("PATCH", f"/repos/{gh.repo}/issues/{iss['number']}",
                    {"state": "closed", "state_reason": "completed"})
