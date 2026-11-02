"""Input validation + small helpers shared across tool lanes.

Validation is strict by design (safety rule 6): no arbitrary flags ever reach a
subprocess; callers pass structured params and we build the argv.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

# RFC-ish hostname: labels 1-63 chars, letters/digits/hyphen, dots between.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})(-(\d{1,5}))?(,(\d{1,5})(-(\d{1,5}))?)*$")
_PRESET_PORTS = {"top-1000", "top-100", "all"}


class ValidationError(Exception):
    pass


def valid_domain(domain: str) -> str:
    d = domain.strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(d):
        raise ValidationError(f"invalid domain: {domain!r}")
    return d


def valid_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as e:
        raise ValidationError(f"invalid IP: {ip!r}") from e


def valid_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.ip_network(cidr.strip(), strict=False))
    except ValueError as e:
        raise ValidationError(f"invalid CIDR: {cidr!r}") from e


def valid_host(host: str) -> str:
    """Domain or IP."""
    h = host.strip()
    try:
        return valid_ip(h)
    except ValidationError:
        return valid_domain(h)


def valid_url(url: str) -> str:
    u = url.strip()
    if not re.match(r"^https?://", u, re.I):
        raise ValidationError(f"url must start with http:// or https://: {url!r}")
    if any(c in u for c in [" ", "`", "$", "\n", ";", "|", "&"]):
        raise ValidationError(f"url contains illegal characters: {url!r}")
    return u


def valid_ports(ports: str) -> str:
    p = ports.strip().lower()
    if p in _PRESET_PORTS:
        return p
    if p == "1-65535" or _PORT_RANGE_RE.match(p):
        # Bounds check every number.
        for n in re.findall(r"\d+", p):
            if int(n) > 65535:
                raise ValidationError(f"port out of range in {ports!r}")
        return p
    raise ValidationError(f"invalid port spec: {ports!r}")


def valid_wordlist(path: str, allowed_dir: Path) -> Path:
    """Wordlist must resolve to a real file INSIDE the allowed wordlists dir."""
    allowed = allowed_dir.resolve()
    candidate = (allowed / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if not str(candidate).startswith(str(allowed) + "/") and candidate != allowed:
        raise ValidationError(
            f"wordlist must be inside {allowed} (got {candidate})"
        )
    if not candidate.is_file():
        raise ValidationError(f"wordlist not found: {candidate}")
    return candidate


def dedupe(items) -> list[str]:
    seen, out = set(), []
    for i in items:
        i = (i or "").strip()
        if i and i.lower() not in seen:
            seen.add(i.lower())
            out.append(i)
    return out


def clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(value, hi))
