"""Subdomain discovery from Certificate Transparency logs.

Two public sources, merged:
  crt.sh       includes expired certificates, which is what surfaces old,
               forgotten hostnames. Free, no key, but slow and often busy.
  Cert Spotter (SSLMate) a second source in case crt.sh is down. Works without
               a key at a low hourly quota; set CERTSPOTTER_API_KEY for more.

Only names under the configured root domains are kept; wildcard labels
("*.") are stripped.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

import dnslite as d

UA = {"User-Agent": "dns-takeover-scanner", "Accept": "application/json"}


class CTError(Exception):
    pass


def _get_json(url: str, headers: dict, timeout: int = 120, attempts: int = 4):
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            last = str(e)
        time.sleep(min(10 * 2 ** i, 120))
    raise CTError(f"{urllib.parse.urlsplit(url).netloc}: {last}")


def keep_under(names, root: str) -> set[str]:
    root = d.normalize(root)
    out = set()
    for raw in names:
        for name in str(raw).split("\n"):  # crt.sh packs several names per field
            n = d.normalize(name)
            while n.startswith("*."):
                n = n[2:]
            if n == root or n.endswith("." + root):
                if all(0 < len(l) <= 63 for l in n.split(".")) and " " not in n:
                    out.add(n)
    return out


def crtsh(root: str) -> set[str]:
    q = urllib.parse.quote(f"%.{root}")
    data = _get_json(f"https://crt.sh/?q={q}&output=json", UA) or []
    names = []
    for row in data:
        names.append(row.get("name_value", ""))
        names.append(row.get("common_name", ""))
    return keep_under(names, root)


def certspotter(root: str, api_key: str | None = None, max_pages: int = 50) -> set[str]:
    headers = dict(UA)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    base = ("https://api.certspotter.com/v1/issuances?"
            + urllib.parse.urlencode({"domain": root, "include_subdomains": "true", "expand": "dns_names"}))
    names, after = [], None
    for _ in range(max_pages):
        url = base + (f"&after={urllib.parse.quote(str(after))}" if after else "")
        page = _get_json(url, headers) or []
        if not page:
            break
        for issuance in page:
            names.extend(issuance.get("dns_names", []))
        after = page[-1].get("id")
    return keep_under(names, root)


def discover(roots: list[str], api_key: str | None = None, sources=None
             ) -> tuple[dict[str, set[str]], list[str], set[str]]:
    """Return ({root: hostnames}, warnings, roots_with_no_working_source).

    The root itself is always included. A root in the third set was only
    partly scanned, so callers must not close earlier findings under it."""
    sources = sources or {"crt.sh": crtsh, "certspotter": lambda r: certspotter(r, api_key)}
    found: dict[str, set[str]] = {}
    warnings: list[str] = []
    failed: set[str] = set()
    for root in roots:
        root = d.normalize(root)
        names = {root}
        ok = 0
        for label, fn in sources.items():
            try:
                names |= fn(root)
                ok += 1
            except CTError as e:
                warnings.append(f"{label} failed for {root}: {e}")
        if ok == 0:
            failed.add(root)
        found[root] = names
    return found, warnings, failed
