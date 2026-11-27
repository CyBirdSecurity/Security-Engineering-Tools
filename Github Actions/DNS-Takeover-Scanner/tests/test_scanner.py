"""Unit tests for the DNS takeover scanner (no network).

Run:  python3 -m unittest discover -s tests   (from the DNS-Takeover-Scanner folder)
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import checks  # noqa: E402
import ct  # noqa: E402
import dnslite as d  # noqa: E402
import issues  # noqa: E402

FPS = checks.load_fingerprints()
PSL = checks.PublicSuffixList("com\nnet\nio\nuk\nco.uk\n*.ck\n!www.ck\n")


def R(rcode=d.NOERROR, answers=(), authority=(), aa=False):
    return d.Response(rcode, aa, False, list(answers), list(authority), [])


def rec(name, rtype, data):
    return d.Record(name, rtype, 300, data)


class FakeResolver:
    """recursive: {(name, type): Response}; direct: {(name, type, ip): Response}.
    Unknown recursive names are NXDOMAIN; names in `broken` raise DNSError."""

    def __init__(self, recursive=None, direct=None, broken=()):
        self.recursive, self.direct, self.broken = recursive or {}, direct or {}, set(broken)

    def resolve(self, name, rtype):
        if name in self.broken:
            raise d.DNSError("timeout")
        if (name, rtype) in self.recursive:
            return self.recursive[(name, rtype)]
        # a name that exists for any type -> NOERROR/no data for other types
        if any(n == name for n, _ in self.recursive):
            return R()
        return R(d.NXDOMAIN)

    def ask(self, name, rtype, ip):
        if (name, rtype, ip) in self.direct:
            return self.direct[(name, rtype, ip)]
        raise d.DNSError("timeout")

    def addresses(self, host):
        r = self.resolve(host, d.A)
        return r.answer_data(d.A), r.rcode


def exists(*names):
    return {(n, d.A): R(answers=[rec(n, d.A, "192.0.2.1")]) for n in names}


# ---------------------------------------------------------------------------

class DnsWireTests(unittest.TestCase):
    def test_query_roundtrip_and_compression(self):
        qid, q = d.build_query("www.example.com", d.MX)
        self.assertEqual(struct.unpack(">H", q[:2])[0], qid)
        # Response: header + question + MX answer using a compression pointer to the question name.
        header = struct.pack(">HHHHHH", qid, 0x8580, 1, 1, 0, 0)
        question = d.encode_name("www.example.com") + struct.pack(">HH", d.MX, 1)
        rdata = struct.pack(">H", 10) + b"\x04mail\xc0\x10"  # mail.<example.com at offset 16>
        answer = b"\xc0\x0c" + struct.pack(">HHIH", d.MX, 1, 300, len(rdata)) + rdata
        resp = d.parse_response(header + question + answer, qid)
        self.assertTrue(resp.aa)
        self.assertEqual(resp.answer_data(d.MX), [(10, "mail.example.com")])

    def test_txt_strings_are_joined(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0)
        txt = b"\x07v=spf1 " + b"\x0finclude:a.test "
        answer = d.encode_name("x.test") + struct.pack(">HHIH", d.TXT, 1, 60, len(txt)) + txt
        self.assertEqual(d.parse_response(header + answer).answer_data(d.TXT), ["v=spf1 include:a.test "])

    def test_truncated_packet_raises(self):
        with self.assertRaises(d.DNSError):
            d.parse_response(b"\x00\x01")

    def test_real_udp_with_tcp_fallback(self):
        """End to end over sockets against a local server that sets TC on UDP."""
        import socket
        import threading

        def answer(query: bytes, truncated: bool) -> bytes:
            qid = query[:2]
            qend = 12 + query[12:].index(b"\0") + 5
            flags = 0x8780 if truncated else 0x8580  # QR AA (+TC) RD RA
            ans = b"" if truncated else b"\xc0\x0c" + struct.pack(">HHIH", d.A, 1, 60, 4) + bytes([192, 0, 2, 7])
            return qid + struct.pack(">HHHHH", flags, 1, 0 if truncated else 1, 0, 0) + query[12:qend] + ans

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", port))
        tcp.listen(1)

        def serve():
            q, addr = udp.recvfrom(512)
            udp.sendto(answer(q, True), addr)
            conn, _ = tcp.accept()
            with conn:
                n = struct.unpack(">H", conn.recv(2))[0]
                reply = answer(conn.recv(n), False)
                conn.sendall(struct.pack(">H", len(reply)) + reply)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            resp = d.query("host.example.com", d.A, "127.0.0.1", timeout=3, attempts=1, port=port)
        finally:
            t.join(5)
            udp.close()
            tcp.close()
        self.assertEqual((resp.rcode, resp.aa, resp.tc, resp.answer_data(d.A)), (d.NOERROR, True, False, ["192.0.2.7"]))


class PslAndParsingTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(PSL.registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(PSL.registrable("x.foo.com"), "foo.com")
        self.assertEqual(PSL.registrable("a.b.c.ck"), "b.c.ck")   # wildcard rule
        self.assertEqual(PSL.registrable("www.ck"), "www.ck")      # exception rule
        self.assertIsNone(PSL.registrable("co.uk"))

    def test_spf_domains(self):
        got = checks.spf_domains("v=spf1 ip4:1.2.3.4 include:_spf.a.test ~include:b.test a:c.test/24 "
                                 "exists:%{i}.d.test redirect=e.test -all")
        self.assertEqual(got, [("include", "_spf.a.test"), ("include", "b.test"), ("a", "c.test"),
                               ("redirect", "e.test")])

    def test_ct_keep_under(self):
        names = ["*.example.com\nwww.example.com", "EXAMPLE.com", "evil-example.com", "a.b.example.com.", "x y"]
        self.assertEqual(ct.keep_under(names, "example.com"), {"example.com", "www.example.com", "a.b.example.com"})

    def test_ancestors(self):
        self.assertEqual(checks.ancestors("a.b.example.com", "example.com"), ["b.example.com", "a.b.example.com"])
        self.assertEqual(checks.ancestors("example.com", "example.com"), [])


class CnameTests(unittest.TestCase):
    def run_check(self, recursive, host="old.example.com", body="", broken=()):
        return checks.check_cname(FakeResolver(recursive, broken=broken), PSL, FPS, host, fetch=lambda h: body)

    def cname(self, src, dst):
        return {(src, d.CNAME): R(answers=[rec(src, d.CNAME, dst)])}

    def test_target_domain_unregistered_is_high(self):
        hr = self.run_check(self.cname("old.example.com", "app.expired-vendor.com"))
        self.assertEqual([(f.type, f.severity, f.target) for f in hr.findings],
                         [("cname-unregistered-domain", "high", "expired-vendor.com")])

    def test_azure_nxdomain_is_high(self):
        rec_ = self.cname("old.example.com", "myapp.azurewebsites.net")
        rec_[("azurewebsites.net", d.NS)] = R(answers=[rec("azurewebsites.net", d.NS, "ns1.x.net")])
        hr = self.run_check(rec_)
        self.assertEqual([(f.type, f.severity, f.service) for f in hr.findings],
                         [("cname-dangling-service", "high", "Azure App Service")])

    def test_generic_nxdomain_is_medium(self):
        rec_ = self.cname("old.example.com", "gone.vendor.com")
        rec_[("vendor.com", d.NS)] = R(answers=[rec("vendor.com", d.NS, "ns1.vendor.com")])
        self.assertEqual([f.type for f in self.run_check(rec_).findings], ["cname-dangling"])

    def test_s3_fingerprint(self):
        rec_ = self.cname("old.example.com", "bucket.s3.amazonaws.com")
        rec_.update(exists("bucket.s3.amazonaws.com"))
        hr = self.run_check(rec_, body="<Code>NoSuchBucket</Code>")
        self.assertEqual([(f.type, f.service) for f in hr.findings], [("cname-dangling-service", "AWS S3")])
        self.assertEqual(self.run_check(rec_, body="<html>ok</html>").findings, [])

    def test_healthy_and_missing_hosts(self):
        rec_ = self.cname("www.example.com", "lb.vendor.com")
        rec_.update(exists("lb.vendor.com"))
        hr = self.run_check(rec_, host="www.example.com")
        self.assertEqual((hr.findings, hr.checked, hr.exists), ([], True, True))
        hr = self.run_check({}, host="gone.example.com")
        self.assertEqual((hr.findings, hr.checked, hr.exists), ([], True, False))

    def test_dns_error_is_inconclusive(self):
        hr = self.run_check({}, host="flaky.example.com", broken={"flaky.example.com"})
        self.assertFalse(hr.checked)


class MailTests(unittest.TestCase):
    def test_mx_and_spf(self):
        recursive = {
            ("example.com", d.MX): R(answers=[rec("example.com", d.MX, (10, "mx.oldmail.com")),
                                              rec("example.com", d.MX, (20, "mx.example.com"))]),
            ("example.com", d.TXT): R(answers=[rec("example.com", d.TXT,
                                                   "v=spf1 include:spf.gone-vendor.com include:spf.ok.com "
                                                   "include:nospf.ok.com -all")]),
            ("spf.ok.com", d.TXT): R(answers=[rec("spf.ok.com", d.TXT, "v=spf1 -all")]),
            ("nospf.ok.com", d.TXT): R(answers=[rec("nospf.ok.com", d.TXT, "google-site-verification=x")]),
            ("ok.com", d.NS): R(answers=[rec("ok.com", d.NS, "ns.ok.com")]),
            **exists("mx.example.com"),
        }
        hr = checks.check_mail(FakeResolver(recursive), PSL, "example.com")
        got = sorted((f.type, f.target) for f in hr.findings)
        self.assertEqual(got, [("mx-unregistered-domain", "oldmail.com"),
                               ("spf-dangling", "nospf.ok.com"),
                               ("spf-unregistered-domain", "gone-vendor.com")])

    def test_null_mx_is_fine(self):
        recursive = {("example.com", d.MX): R(answers=[rec("example.com", d.MX, (0, ""))])}
        self.assertEqual(checks.check_mail(FakeResolver(recursive), PSL, "example.com").findings, [])


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.recursive = {
            ("example.com", d.NS): R(answers=[rec("example.com", d.NS, "ns1.example.com")]),
            **exists("ns1.example.com", "ns-1.awsdns-01.com", "ns.child-host.com"),
        }
        self.direct = {}

    def delegate(self, zone, ns_hosts):
        self.direct[(zone, d.NS, "192.0.2.1")] = R(authority=[rec(zone, d.NS, h) for h in ns_hosts])

    def check(self, host):
        dc = checks.DelegationChecker(FakeResolver(self.recursive, self.direct), PSL, FPS)
        return dc.check_host(host, "example.com"), dc

    def test_route53_delegation_not_served_is_high(self):
        self.delegate("dev.example.com", ["ns-1.awsdns-01.com"])
        found, _ = self.check("api.dev.example.com")
        self.assertEqual([(f.type, f.host, f.service) for f in found],
                         [("ns-dangling-provider", "dev.example.com", "AWS Route 53")])

    def test_healthy_delegation(self):
        self.delegate("dev.example.com", ["ns.child-host.com"])
        self.direct[("dev.example.com", d.SOA, "192.0.2.1")] = R(
            answers=[rec("dev.example.com", d.SOA, ("ns.child-host.com", "h", 1, 2, 3, 4, 5))], aa=True)
        self.direct[("api.dev.example.com", d.NS, "192.0.2.1")] = R()
        found, dc = self.check("api.dev.example.com")
        self.assertEqual((found, dc.errors), ([], []))

    def test_ns_domain_unregistered(self):
        self.delegate("old.example.com", ["ns1.lapsed-dns.com"])
        found, _ = self.check("old.example.com")
        self.assertEqual([(f.type, f.target) for f in found], [("ns-unregistered-domain", "lapsed-dns.com")])

    def test_unknown_provider_is_lame_medium(self):
        self.delegate("x.example.com", ["ns.child-host.com"])
        found, _ = self.check("x.example.com")
        self.assertEqual([(f.type, f.severity) for f in found], [("ns-lame-delegation", "medium")])

    def test_not_delegated_and_nxdomain(self):
        self.direct[("www.example.com", d.NS, "192.0.2.1")] = R(aa=True)
        self.direct[("gone.example.com", d.NS, "192.0.2.1")] = R(d.NXDOMAIN, aa=True)
        self.assertEqual(self.check("www.example.com")[0], [])
        self.assertEqual(self.check("a.gone.example.com")[0], [])


class IssuePlanTests(unittest.TestCase):
    def issue(self, fid, host, state="open", reason=None, number=1):
        return {"number": number, "state": state, "state_reason": reason,
                "body": f"x <!-- dns-takeover-id: {fid} host: {host} -->"}

    def test_all_branches(self):
        f = lambda fid, host: {"id": fid, "host": host}  # noqa: E731
        findings = {"a" * 16: f("a" * 16, "new.example.com"), "b" * 16: f("b" * 16, "still.example.com"),
                    "c" * 16: f("c" * 16, "accepted.example.com"), "d" * 16: f("d" * 16, "back.example.com")}
        existing = [self.issue("b" * 16, "still.example.com"),
                    self.issue("c" * 16, "accepted.example.com", "closed", "not_planned"),
                    self.issue("d" * 16, "back.example.com", "closed", "completed"),
                    self.issue("e" * 16, "fixed.example.com"),
                    self.issue("f" * 16, "flaky.example.com")]
        got = {(a, (fi or {}).get("host") or issues.parse_marker(i["body"])[1])
               for a, fi, i in issues.plan_actions(findings, existing, {"fixed.example.com"})}
        self.assertEqual(got, {("create", "new.example.com"), ("update", "still.example.com"),
                               ("suppressed", "accepted.example.com"), ("reopen", "back.example.com"),
                               ("close", "fixed.example.com"), ("keep", "flaky.example.com")})

    def test_body_has_marker_and_first_seen(self):
        fd = checks.Finding("cname-dangling", "medium", "h.example.com", "CNAME h -> t", "t.vendor.com").to_dict()
        body = issues.issue_body(fd, "2026-01-01 00:00 UTC", "2026-02-01 00:00 UTC", "url")
        self.assertEqual(issues.parse_marker(body), (fd["id"], "h.example.com"))
        self.assertEqual(issues.FIRST_SEEN_RX.search(body).group(1).strip(), "2026-01-01 00:00 UTC")


if __name__ == "__main__":
    unittest.main()
