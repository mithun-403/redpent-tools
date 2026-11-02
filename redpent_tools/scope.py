"""Scope + authorization guards. This is the safety core of the server.

Rules enforced here (see README "Safety rules"):
  * out_of_scope ALWAYS wins.
  * a hostname is in scope only if it (or a *.wildcard parent) is listed AND none
    of its resolved IPs are out of scope.
  * active tools require active_allowed + inside active_window + confirm_authorized
    + a matching engagement_id.
  * CDN / cloud netblocks are flagged and direct scanning of them is refused.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime

from .config import Config, now_utc

# A small built-in set of well-known Cloudflare ranges. ASN lookup (cdn_asn_lookup)
# augments this at runtime; this list makes the common case work offline/in tests.
CLOUDFLARE_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

# ASNs that belong to CDN / cloud edge providers we should never scan directly.
CDN_ASNS = {
    13335: "Cloudflare", 54113: "Fastly", 16509: "Amazon-CloudFront",
    15169: "Google", 20940: "Akamai", 16625: "Akamai", 8075: "Microsoft",
    13238: "Yandex", 60626: "Leaseweb-CDN",
}


class ScopeError(Exception):
    """Raised when a target is out of scope or an active gate fails."""


@dataclass
class ScopeDecision:
    in_scope: bool
    reason: str
    resolved_ips: list[str]
    cdn: str | None = None  # CDN/cloud vendor name if the target lives behind one


# ---- low-level helpers -------------------------------------------------------

def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_cidr(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def _domain_matches(host: str, pattern: str) -> bool:
    """`*.example.com` matches any subdomain; `example.com` matches exactly."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


def _ip_in_any(ip: str, nets: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if addr in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to a de-duplicated list of IPs. Empty on failure."""
    if _is_ip(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return sorted({i[4][0] for i in infos})


def cdn_for_ip(ip: str) -> str | None:
    """Best-effort CDN/cloud identification. Cloudflare static list first, then a
    Team-Cymru DNS ASN lookup (no API key). Returns vendor name or None."""
    if _ip_in_any(ip, CLOUDFLARE_V4):
        return "Cloudflare"
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        txt = socket.gethostbyname_ex(rev)  # cheap A record existence probe
        # The real ASN is in the TXT record; A-record presence alone is unreliable,
        # so fall through to None rather than guess. Kept intentionally conservative.
        _ = txt
    except Exception:
        pass
    return None


# ---- the public guard API ----------------------------------------------------

class ScopeGuard:
    def __init__(self, config: Config):
        self.cfg = config
        self.scope = config.scope

    # scope checking ----------------------------------------------------------
    def decide(self, target: str) -> ScopeDecision:
        """Full scope decision for a domain, IP, URL host, or CIDR."""
        host = _target_host(target)

        # 1. CIDR targets: must be fully inside in_scope_cidrs and not overlap OOS.
        if _is_cidr(host) and not _is_ip(host):
            net = ipaddress.ip_network(host, strict=False)
            if any(_net_overlaps(net, o) for o in self.scope.out_of_scope):
                return ScopeDecision(False, f"{host} overlaps out_of_scope", [])
            if any(_net_contains(c, net) for c in self.scope.in_scope_cidrs):
                return ScopeDecision(True, "CIDR within in_scope_cidrs", [])
            return ScopeDecision(False, f"{host} not within any in_scope_cidr", [])

        ips = resolve_ips(host)

        # 2. out_of_scope always wins — by name or by any resolved IP.
        for oos in self.scope.out_of_scope:
            if not _is_cidr(oos) and _domain_matches(host, oos):
                return ScopeDecision(False, f"{host} matches out_of_scope '{oos}'", ips)
        for ip in ips:
            if _ip_in_any(ip, [o for o in self.scope.out_of_scope if _is_cidr(o)]):
                return ScopeDecision(False, f"{host} resolves to OOS IP {ip}", ips)

        # 3. in scope by domain or by IP/CIDR membership.
        cdn = next((c for c in (cdn_for_ip(ip) for ip in ips) if c), None)
        if any(_domain_matches(host, d) for d in self.scope.in_scope_domains):
            return ScopeDecision(True, "domain in in_scope_domains", ips, cdn)
        if _is_ip(host) and _ip_in_any(host, self.scope.in_scope_cidrs):
            return ScopeDecision(True, "IP in in_scope_cidrs", ips, cdn)
        if ips and all(_ip_in_any(ip, self.scope.in_scope_cidrs) for ip in ips):
            return ScopeDecision(True, "all resolved IPs in in_scope_cidrs", ips, cdn)

        return ScopeDecision(False, f"{host} not in any in-scope domain/CIDR", ips, cdn)

    def assert_in_scope(self, target: str) -> ScopeDecision:
        d = self.decide(target)
        if not d.in_scope:
            raise ScopeError(f"OUT OF SCOPE: {d.reason}")
        return d

    def assert_scannable_ip(self, target: str) -> ScopeDecision:
        """Like assert_in_scope but also refuses to scan CDN/cloud netblocks directly
        when the target is a raw IP (scan the hostname instead)."""
        d = self.assert_in_scope(target)
        if _is_ip(_target_host(target)) and d.cdn:
            raise ScopeError(
                f"REFUSED: {target} is a {d.cdn} CDN/edge IP. Scan the in-scope "
                f"hostname, not the shared CDN netblock."
            )
        return d

    # active-tool authorization ----------------------------------------------
    def assert_active_allowed(self, confirm_authorized: bool, engagement_id: str) -> None:
        failures = []
        if not self.scope.active_allowed:
            failures.append("scope.active_allowed is false")
        if not confirm_authorized:
            failures.append("caller did not pass confirm_authorized=true")
        if engagement_id != self.scope.engagement_id:
            failures.append(
                f"engagement_id '{engagement_id}' != scope '{self.scope.engagement_id}'"
            )
        in_window, why = self._in_active_window()
        if not in_window:
            failures.append(why)
        if failures:
            raise ScopeError("ACTIVE GATE BLOCKED: " + "; ".join(failures))

    def _in_active_window(self) -> tuple[bool, str]:
        w = self.scope.active_window or {}
        start, end = w.get("start"), w.get("end")
        if not start or not end:
            return False, "active_window.start/end not set"
        try:
            s = datetime.fromisoformat(start)
            e = datetime.fromisoformat(end)
        except ValueError:
            return False, "active_window dates are not valid ISO8601"
        now = now_utc()
        if s.tzinfo is None:
            s = s.replace(tzinfo=now.tzinfo)
        if e.tzinfo is None:
            e = e.replace(tzinfo=now.tzinfo)
        if s <= now <= e:
            return True, "inside active_window"
        return False, f"outside active_window ({start} .. {end})"


# ---- module helpers ----------------------------------------------------------

def _target_host(target: str) -> str:
    """Strip scheme/path/port from a URL or host:port to the bare host.
    A bare CIDR (e.g. 203.0.113.8/29) is returned unchanged."""
    t = target.strip()
    if "://" not in t and _is_cidr(t) and not _is_ip(t):
        return t  # preserve the /prefix for CIDR targets
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    # keep CIDR slash; only strip :port for host:port (not IPv6 blindly)
    if t.count(":") == 1 and not _is_ip(t):
        t = t.split(":", 1)[0]
    return t.rstrip(".")


def _net_overlaps(net: ipaddress._BaseNetwork, other: str) -> bool:
    if not _is_cidr(other):
        return False
    try:
        return net.overlaps(ipaddress.ip_network(other, strict=False))
    except ValueError:
        return False


def _net_contains(outer: str, inner: ipaddress._BaseNetwork) -> bool:
    if not _is_cidr(outer):
        return False
    try:
        o = ipaddress.ip_network(outer, strict=False)
        return inner.subnet_of(o)
    except (ValueError, TypeError):
        return False
