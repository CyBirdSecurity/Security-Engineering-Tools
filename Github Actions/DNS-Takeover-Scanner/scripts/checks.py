"""Takeover checks. Every function takes a resolver object, so tests can pass
a fake one; nothing here opens sockets directly except `http_body`.

Finding types:
  cname-unregistered-domain   CNAME target's registrable domain doesn't exist (can be registered)   high
  cname-dangling-service      CNAME to a cloud/SaaS resource that no longer exists                   high/medium
  cname-dangling              CNAME target doesn't exist (no known service)                          medium
  ns-unregistered-domain      delegated name server's domain doesn't exist (can be registered)       high
  ns-dangling-provider        delegated to a cloud DNS provider that doesn't serve the zone          high
  ns-lame-delegation          no delegated name server answers for the zone                          medium
  mx-unregistered-domain      MX host's domain doesn't exist (can be registered)                      high
  mx-dangling                 MX host doesn't resolve                                                medium
  spf-unregistered-domain     SPF include/redirect domain doesn't exist (can be registered)         high
  spf-dangling                SPF include/redirect domain has no SPF record                          medium
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import urllib.request
from dataclasses import asdict, dataclass, field

import dnslite as d

HERE = os.path.dirname(os.path.abspath(__file__))


@dataclass
class Finding:
    type: str
    severity: str           # high | medium
    host: str               # the name in your zone that is exposed
    record: str             # e.g. "CNAME old.example.com -> foo.azurewebsites.net"
    target: str             # the dangling thing
    service: str = ""
    evidence: str = ""
    remediation: str = ""

    @property
    def id(self) -> str:
        return hashlib.sha256(f"{self.type}|{self.host}|{self.target}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {**asdict(self), "id": self.id}


@dataclass
class HostResult:
    host: str
    checked: bool = True     # False when DNS errors prevented a conclusive check
    exists: bool = False
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Fingerprints and the Public Suffix List
# ---------------------------------------------------------------------------

def load_fingerprints(path: str | None = None) -> dict:
    with open(path or os.path.join(HERE, "fingerprints.json"), encoding="utf-8") as f:
        data = json.load(f)
    for svc in data["services"]:
        svc["_rx"] = [re.compile(p) for p in svc["cname"]]
    for p in data["dns_providers"]:
        p["_rx"] = [re.compile(x) for x in p["ns"]]
    return data


def match_service(names: list[str], fps: dict) -> dict | None:
    for name in names:
        for svc in fps["services"]:
            if any(rx.search(name) for rx in svc["_rx"]):
                return svc
    return None


def match_dns_provider(ns_hosts: list[str], fps: dict) -> dict | None:
    for host in ns_hosts:
        for p in fps["dns_providers"]:
            if any(rx.search(host) for rx in p["_rx"]):
                return p
    return None


# Used when the full list can't be downloaded: the most common multi-label suffixes.
FALLBACK_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.sg", "com.tr", "co.kr", "com.hk", "com.tw",
}


class PublicSuffixList:
    """Finds a name's registrable domain ("eTLD+1"), e.g. a.b.example.co.uk -> example.co.uk."""

    def __init__(self, text: str | None = None):
        self.rules: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        if text:
            for line in text.splitlines():
                line = line.strip().lower()
                if not line or line.startswith("//"):
                    continue
                rule = line.split()[0]
                if rule.startswith("!"):
                    self.exceptions.add(rule[1:])
                elif rule.startswith("*."):
                    self.wildcards.add(rule[2:])
                else:
                    self.rules.add(rule)
        else:
            self.rules = set(FALLBACK_SUFFIXES)

    @classmethod
    def download(cls, url: str = "https://publicsuffix.org/list/public_suffix_list.dat") -> "PublicSuffixList":
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return cls(r.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - fall back to the built-in list
            return cls(None)

    def suffix_len(self, labels: list[str]) -> int:
        """Number of labels in the public suffix of `labels` (at least 1)."""
        best = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            n = len(labels) - i
            if cand in self.exceptions:
                return n - 1
            if cand in self.rules:
                best = max(best, n)
            if i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wildcards:
                best = max(best, n)
        return best

    def registrable(self, name: str) -> str | None:
        labels = d.normalize(name).split(".")
        n = self.suffix_len(labels)
        if len(labels) <= n:
            return None  # the name is itself a public suffix
        return ".".join(labels[-(n + 1):])


def domain_unregistered(res, psl: PublicSuffixList, name: str) -> bool | None:
    """True if `name`'s registrable domain doesn't exist in DNS, which usually
    means it can be registered by anyone. None when DNS gave no clear answer."""
    reg = psl.registrable(name)
    if not reg:
        return None
    try:
        r = res.resolve(reg, d.NS)
    except d.DNSError:
        return None
    if r.rcode == d.NXDOMAIN:
        return True
    if r.rcode == d.NOERROR:
        return False
    return None


# ---------------------------------------------------------------------------
# HTTP fingerprinting (only for hosts whose CNAME points at a known service)
# ---------------------------------------------------------------------------

def http_body(host: str, timeout: float = 10.0, limit: int = 256 * 1024) -> str:
    """Fetch http:// then https:// for `host` and return the first body read.

    Certificate verification is off on purpose: an unclaimed resource on a
    shared platform serves the platform's certificate, not yours, and we only
    read the error page. No credentials or cookies are sent.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("http", "https"):
        req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": "dns-takeover-scanner"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read(limit).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:  # error pages are exactly what we want
            try:
                return e.read(limit).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
        except Exception:  # noqa: BLE001
            continue
    return ""


# ---------------------------------------------------------------------------
# CNAME check
# ---------------------------------------------------------------------------

def cname_chain(res, host: str, limit: int = 10) -> tuple[list[str], int]:
    """Follow CNAMEs from host. Returns (chain of targets, rcode of host lookup)."""
    chain, current = [], host
    first = res.resolve(host, d.CNAME)
    rcode = first.rcode
    resp = first
    for _ in range(limit):
        targets = resp.answer_data(d.CNAME, current)
        if not targets:
            break
        current = targets[0]
        chain.append(current)
        resp = res.resolve(current, d.CNAME)
    return chain, rcode


def check_cname(res, psl, fps, host: str, fetch=http_body) -> HostResult:
    hr = HostResult(host)
    try:
        chain, rcode = cname_chain(res, host)
    except d.DNSError as e:
        hr.checked = False
        hr.errors.append(str(e))
        return hr
    if rcode == d.NXDOMAIN:
        return hr  # the name doesn't exist any more: nothing to take over
    hr.exists = rcode == d.NOERROR
    if not chain:
        return hr
    final = chain[-1]
    record = f"CNAME {host} -> {' -> '.join(chain)}"
    svc = match_service(chain, fps)
    try:
        _, final_rcode = res.addresses(final)
    except d.DNSError as e:
        hr.checked = False
        hr.errors.append(str(e))
        return hr

    if final_rcode == d.NXDOMAIN:
        unreg = domain_unregistered(res, psl, final)
        if unreg:
            hr.findings.append(Finding(
                "cname-unregistered-domain", "high", host, record, psl.registrable(final) or final,
                evidence=f"{final} is NXDOMAIN and its domain {psl.registrable(final)} has no NS records "
                         "(looks unregistered).",
                remediation=f"Delete the CNAME for {host}, or register {psl.registrable(final)} yourself."))
        elif svc and svc["nxdomain"]:
            hr.findings.append(Finding(
                "cname-dangling-service", "high" if svc["status"] == "vulnerable" else "medium", host, record,
                final, svc["name"],
                evidence=f"{final} is NXDOMAIN; on {svc['name']} that resource name can be claimed by anyone.",
                remediation=f"Delete the CNAME for {host}, or recreate the {svc['name']} resource it points to."))
        else:
            hr.findings.append(Finding(
                "cname-dangling", "medium", host, record, final, svc["name"] if svc else "",
                evidence=f"{final} is NXDOMAIN.",
                remediation=f"Delete the CNAME for {host} if the target is gone for good."))
        return hr

    if svc and svc["http"]:
        body = fetch(host)
        hit = next((s for s in svc["http"] if s in body), None)
        if hit:
            hr.findings.append(Finding(
                "cname-dangling-service", "high" if svc["status"] == "vulnerable" else "medium", host, record,
                final, svc["name"],
                evidence=f"{host} serves the {svc['name']} 'unclaimed' page (matched: {hit!r}).",
                remediation=f"Delete the CNAME for {host}, or reclaim the {svc['name']} resource "
                            "(bucket, site or app) it points to."))
    return hr


# ---------------------------------------------------------------------------
# NS delegation check
# ---------------------------------------------------------------------------

def ancestors(host: str, root: str) -> list[str]:
    """Names from one label below root down to host: a.b.root -> [b.root, a.b.root]."""
    host, root = d.normalize(host), d.normalize(root)
    if host == root or not host.endswith("." + root):
        return []
    extra = host[: -len(root) - 1].split(".")
    return [".".join(extra[i:]) + "." + root for i in range(len(extra) - 1, -1, -1)]


def server_ips(res, ns_hosts: list[str]) -> list[str]:
    ips = []
    for h in ns_hosts:
        try:
            ips += res.addresses(h)[0]
        except d.DNSError:
            pass
    return ips


def zone_answers(res, zone: str, ips: list[str]) -> bool:
    """True if any of the servers answers authoritatively for the zone's SOA."""
    for ip in ips:
        try:
            r = res.ask(zone, d.SOA, ip)
        except d.DNSError:
            continue
        if r.rcode == d.NOERROR and r.aa and r.answer_data(d.SOA, zone):
            return True
    return False


class DelegationChecker:
    """Walks down from each root zone the way a resolver would, asking each
    zone's own servers about the next label. That finds delegations even when
    they're broken (a recursive resolver just answers SERVFAIL for those)."""

    def __init__(self, res, psl, fps):
        self.res, self.psl, self.fps = res, psl, fps
        self._zone_servers: dict[str, list[str] | None] = {}
        self._findings: dict[str, Finding] = {}
        self.errors: list[str] = []

    def root_servers(self, root: str) -> list[str] | None:
        if root not in self._zone_servers:
            try:
                ns = self.res.resolve(root, d.NS).answer_data(d.NS, root)
            except d.DNSError as e:
                self.errors.append(f"NS {root}: {e}")
                ns = []
            self._zone_servers[root] = server_ips(self.res, ns) or None
            if self._zone_servers[root] is None:
                self.errors.append(f"could not find working name servers for {root}")
        return self._zone_servers[root]

    def check_host(self, host: str, root: str) -> list[Finding]:
        servers = self.root_servers(root)
        if not servers:
            return []
        out = []
        for name in ancestors(host, root):
            if name in self._zone_servers:  # already walked
                if name in self._findings:
                    out.append(self._findings[name])
                servers = self._zone_servers[name]
                if servers is None:
                    break
                continue
            resp = None
            for ip in servers:
                try:
                    resp = self.res.ask(name, d.NS, ip)
                    break
                except d.DNSError:
                    continue
            if resp is None:
                self.errors.append(f"no answer from parent servers for {name}")
                break
            if resp.rcode == d.NXDOMAIN:
                self._zone_servers[name] = None
                break
            child_ns = [r.data for r in resp.authority + resp.answers if r.rtype == d.NS and r.name == name]
            if not child_ns:
                continue  # same zone, keep walking with the same servers
            finding, child_ips = self._check_delegation(name, sorted(set(child_ns)))
            if finding:
                self._findings[name] = finding
                out.append(finding)
                self._zone_servers[name] = None
                break
            self._zone_servers[name] = child_ips
            servers = child_ips
        return out

    def _check_delegation(self, zone: str, ns_hosts: list[str]) -> tuple[Finding | None, list[str]]:
        record = f"NS {zone} -> {', '.join(ns_hosts)}"
        for h in ns_hosts:
            try:
                _, rc = self.res.addresses(h)
            except d.DNSError:
                continue
            if rc == d.NXDOMAIN and domain_unregistered(self.res, self.psl, h):
                reg = self.psl.registrable(h)
                return Finding("ns-unregistered-domain", "high", zone, record, reg or h,
                               evidence=f"Name server {h} doesn't exist and its domain {reg} looks unregistered. "
                                        "Whoever registers it controls every record under " + zone + ".",
                               remediation=f"Remove or fix the NS records for {zone} in the parent zone."), []
        ips = server_ips(self.res, ns_hosts)
        if zone_answers(self.res, zone, ips):
            return None, ips
        provider = match_dns_provider(ns_hosts, self.fps)
        if provider:
            return Finding("ns-dangling-provider", "high", zone, record, ", ".join(ns_hosts), provider["name"],
                           evidence=f"{zone} is delegated to {provider['name']}, but none of those name servers "
                                    "serve the zone. Someone could create the zone on that provider and get "
                                    "the same name servers assigned.",
                           remediation=f"Remove the NS records for {zone} from the parent zone, or recreate the "
                                       f"zone on {provider['name']}."), []
        return Finding("ns-lame-delegation", "medium", zone, record, ", ".join(ns_hosts),
                       evidence=f"None of the delegated name servers answer authoritatively for {zone}.",
                       remediation=f"Remove or fix the NS records for {zone} in the parent zone."), []


# ---------------------------------------------------------------------------
# MX and SPF
# ---------------------------------------------------------------------------

SPF_DOMAIN_RX = re.compile(r"^(?:[+\-~?]?)(include:|redirect=|a:|mx:|exists:)([^/\s]+)", re.I)


def spf_domains(txt: str) -> list[tuple[str, str]]:
    """[(mechanism, domain)] referenced by an SPF record. Macros are skipped."""
    out = []
    for token in txt.split()[1:]:
        m = SPF_DOMAIN_RX.match(token)
        if m and "%{" not in m.group(2):
            out.append((m.group(1).rstrip(":=").lower(), d.normalize(m.group(2))))
    return out


def check_mail(res, psl, host: str) -> HostResult:
    hr = HostResult(host)
    try:
        mx = res.resolve(host, d.MX)
        txt = res.resolve(host, d.TXT)
    except d.DNSError as e:
        hr.checked = False
        hr.errors.append(str(e))
        return hr
    for _pref, exch in mx.answer_data(d.MX, host):
        if not exch or exch == ".":
            continue  # null MX (RFC 7505): domain accepts no mail
        try:
            _, rc = res.addresses(exch)
        except d.DNSError as e:
            hr.errors.append(str(e))
            continue
        if rc == d.NXDOMAIN:
            if domain_unregistered(res, psl, exch):
                reg = psl.registrable(exch)
                hr.findings.append(Finding(
                    "mx-unregistered-domain", "high", host, f"MX {host} -> {exch}", reg or exch,
                    evidence=f"Mail server {exch} doesn't exist and {reg} looks unregistered; whoever registers "
                             f"it receives mail for {host}.",
                    remediation=f"Remove the MX record for {host} or point it at a working mail server."))
            else:
                hr.findings.append(Finding(
                    "mx-dangling", "medium", host, f"MX {host} -> {exch}", exch,
                    evidence=f"Mail server {exch} doesn't resolve.",
                    remediation=f"Remove or fix the MX record for {host}."))
    for record in txt.answer_data(d.TXT, host):
        if not record.lower().startswith("v=spf1"):
            continue
        for mech, dom in spf_domains(record):
            try:
                r = res.resolve(dom, d.TXT if mech in ("include", "redirect") else d.A)
            except d.DNSError as e:
                hr.errors.append(str(e))
                continue
            rec = f"SPF {host}: {mech}:{dom}"
            if r.rcode == d.NXDOMAIN:
                if domain_unregistered(res, psl, dom):
                    reg = psl.registrable(dom)
                    hr.findings.append(Finding(
                        "spf-unregistered-domain", "high", host, rec, reg or dom,
                        evidence=f"SPF for {host} trusts {dom}, whose domain {reg} looks unregistered; whoever "
                                 f"registers it can send mail that passes SPF as {host}.",
                        remediation=f"Remove {mech}:{dom} from the SPF record of {host}."))
                elif mech in ("include", "redirect"):
                    hr.findings.append(Finding(
                        "spf-dangling", "medium", host, rec, dom,
                        evidence=f"SPF {mech} target {dom} doesn't exist (SPF evaluation will fail).",
                        remediation=f"Remove {mech}:{dom} from the SPF record of {host}."))
            elif mech in ("include", "redirect") and r.rcode == d.NOERROR:
                if not any(t.lower().startswith("v=spf1") for t in r.answer_data(d.TXT, dom)):
                    hr.findings.append(Finding(
                        "spf-dangling", "medium", host, rec, dom,
                        evidence=f"SPF {mech} target {dom} has no SPF record.",
                        remediation=f"Remove {mech}:{dom} from the SPF record of {host}, or fix {dom}."))
    return hr
