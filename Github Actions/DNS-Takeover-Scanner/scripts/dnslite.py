"""Minimal DNS client (standard library only).

Why not the system resolver: the delegation check has to send
non-recursive queries straight to a zone's authoritative name servers and
read referrals, which `socket.getaddrinfo` can't do. This is enough DNS
for that: A, AAAA, NS, CNAME, SOA, MX and TXT over UDP, with TCP fallback
for truncated answers.
"""

from __future__ import annotations

import random
import socket
import struct
import threading
from dataclasses import dataclass, field

A, NS, CNAME, SOA, MX, TXT, AAAA = 1, 2, 5, 6, 15, 16, 28
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", MX: "MX", TXT: "TXT", AAAA: "AAAA"}

NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    """No usable answer (timeout, network error, malformed packet)."""


@dataclass
class Record:
    name: str
    rtype: int
    ttl: int
    data: object  # str for names/addresses, (pref, host) for MX, str for TXT, tuple for SOA


@dataclass
class Response:
    rcode: int
    aa: bool
    tc: bool
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, str(self.rcode))

    def answer_data(self, rtype: int, name: str | None = None) -> list:
        return [r.data for r in self.answers if r.rtype == rtype and (name is None or r.name == normalize(name))]


def normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def encode_name(name: str) -> bytes:
    out = b""
    for label in normalize(name).split("."):
        if not label:
            continue
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def build_query(name: str, rtype: int, recursion_desired: bool = True, qid: int | None = None) -> tuple[int, bytes]:
    qid = random.getrandbits(16) if qid is None else qid
    flags = 0x0100 if recursion_desired else 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    return qid, header + encode_name(name) + struct.pack(">HH", rtype, 1)


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels, jumped, end, seen = [], False, offset, 0
    while True:
        if offset >= len(msg):
            raise DNSError("truncated name")
        length = msg[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(msg):
                raise DNSError("truncated pointer")
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                end = offset + 2
            offset, jumped = ptr, True
            seen += 1
            if seen > 64:
                raise DNSError("compression loop")
            continue
        if length == 0:
            if not jumped:
                end = offset + 1
            return ".".join(labels).lower(), end
        offset += 1
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length


def _parse_rdata(msg: bytes, rtype: int, offset: int, rdlen: int):
    rd = msg[offset:offset + rdlen]
    if rtype == A and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, rd)
    if rtype == AAAA and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (NS, CNAME):
        return _read_name(msg, offset)[0]
    if rtype == MX:
        pref = struct.unpack(">H", rd[:2])[0]
        return pref, _read_name(msg, offset + 2)[0]
    if rtype == TXT:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(rd[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == SOA:
        mname, o = _read_name(msg, offset)
        rname, o = _read_name(msg, o)
        return (mname, rname) + struct.unpack(">IIIII", msg[o:o + 20])
    return rd


def parse_response(msg: bytes, expect_id: int | None = None) -> Response:
    if len(msg) < 12:
        raise DNSError("short response")
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    if expect_id is not None and qid != expect_id:
        raise DNSError("response id mismatch")
    resp = Response(rcode=flags & 0x000F, aa=bool(flags & 0x0400), tc=bool(flags & 0x0200))
    offset = 12
    for _ in range(qd):
        _, offset = _read_name(msg, offset)
        offset += 4
    for count, bucket in ((an, resp.answers), (ns, resp.authority), (ar, resp.additional)):
        for _ in range(count):
            name, offset = _read_name(msg, offset)
            if offset + 10 > len(msg):
                raise DNSError("truncated record")
            rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[offset:offset + 10])
            offset += 10
            bucket.append(Record(name, rtype, ttl, _parse_rdata(msg, rtype, offset, rdlen)))
            offset += rdlen
    return resp


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _udp(server: str, packet: bytes, timeout: float, port: int = 53) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        return s.recv(65535)


def _tcp(server: str, packet: bytes, timeout: float, port: int = 53) -> bytes:
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(struct.pack(">H", len(packet)) + packet)
        size = struct.unpack(">H", _recv_exact(s, 2))[0]
        return _recv_exact(s, size)


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise DNSError("connection closed")
        buf += chunk
    return buf


def query(name: str, rtype: int, server: str, recursion_desired: bool = True,
          timeout: float = 3.0, attempts: int = 2, port: int = 53) -> Response:
    last: Exception | None = None
    for _ in range(attempts):
        qid, packet = build_query(name, rtype, recursion_desired)
        try:
            resp = parse_response(_udp(server, packet, timeout, port), qid)
            if resp.tc:
                resp = parse_response(_tcp(server, packet, timeout, port), qid)
            return resp
        except (OSError, DNSError) as e:
            last = e
    raise DNSError(f"{TYPE_NAMES.get(rtype, rtype)} {name} @{server}: {last}")


class Resolver:
    """Recursive lookups through public resolvers, plus direct
    non-recursive queries to specific servers. Thread-safe cache."""

    def __init__(self, servers: list[str], timeout: float = 3.0):
        if not servers:
            raise ValueError("at least one resolver is required")
        self.servers = servers
        self.timeout = timeout
        self._cache: dict[tuple, Response] = {}
        self._lock = threading.Lock()

    def resolve(self, name: str, rtype: int) -> Response:
        """Recursive query; tries each configured resolver until one answers
        with something other than SERVFAIL."""
        key = ("r", normalize(name), rtype)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        resp, errors = None, []
        for server in self.servers:
            try:
                resp = query(name, rtype, server, True, self.timeout)
                if resp.rcode != SERVFAIL:
                    break
            except DNSError as e:
                errors.append(str(e))
        if resp is None:
            raise DNSError("; ".join(errors))
        with self._lock:
            self._cache[key] = resp
        return resp

    def ask(self, name: str, rtype: int, server_ip: str) -> Response:
        """Non-recursive query to one specific (authoritative) server."""
        key = ("d", normalize(name), rtype, server_ip)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        resp = query(name, rtype, server_ip, False, self.timeout)
        with self._lock:
            self._cache[key] = resp
        return resp

    def addresses(self, host: str) -> tuple[list[str], int]:
        """IPv4 (then IPv6) addresses for a host, plus the rcode of the A lookup."""
        resp = self.resolve(host, A)
        ips = [d for d in resp.answer_data(A)]
        if not ips and resp.rcode == NOERROR:
            ips = [d for d in self.resolve(host, AAAA).answer_data(AAAA)]
        return ips, resp.rcode
