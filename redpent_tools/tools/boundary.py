"""BOUNDARY lane — light-touch requests to in-scope hosts only (low rate, no fuzzing).

These send a small number of benign requests (a probe, a HEAD, a TLS handshake). They
are scope-checked and audited, but do NOT require the active authorization gate.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import httpx

from ..context import ReconContext
from ..scope import ScopeError
from . import utils
from .utils import ValidationError

UA = "redpent-tools/0.1 (authorized-assessment)"

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


def _block(ctx, tool, args, target, exc):
    status = "blocked" if isinstance(exc, (ScopeError, ValidationError)) else "error"
    ctx.auditor.record(tool, args, target, status, note=str(exc))
    return {"ok": False, "status": status, "error": str(exc)}


# ---- httpx probe -------------------------------------------------------------

async def httpx_probe(ctx: ReconContext, hosts: list[str]) -> dict[str, Any]:
    args = {"hosts": hosts}
    allowed = []
    for h in hosts:
        try:
            hv = utils.valid_host(h)
            ctx.guard.assert_in_scope(hv)
            allowed.append(hv)
        except Exception:
            continue
    if not allowed:
        return _block(ctx, "httpx_probe", args, None, ScopeError("no in-scope hosts"))

    # feed hosts on stdin-equivalent: httpx -l needs a file; write a temp list in evidence
    list_file = ctx.config.evidence_path("httpx_probe") / "targets.txt"
    list_file.write_text("\n".join(allowed))
    cmd = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
           "-location", "-rate-limit", "20", "-l", str(list_file)]
    res = await ctx.runner.run("httpx_probe", cmd, timeout=600)
    rows = []
    for line in res.raw_stdout.splitlines():
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        rows.append({"host": d.get("input") or d.get("host"), "url": d.get("url"),
                     "status": d.get("status_code"), "title": d.get("title"),
                     "tech": d.get("tech"), "location": d.get("location")})
    ctx.auditor.record("httpx_probe", args, ",".join(allowed[:5]), "ok",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": True, "results": rows, "evidence_file": res.evidence_file}


# ---- HTTP headers ------------------------------------------------------------

async def http_headers(ctx: ReconContext, url: str) -> dict[str, Any]:
    args = {"url": url}
    try:
        url = utils.valid_url(url)
        ctx.guard.assert_in_scope(url)
    except Exception as e:
        return _block(ctx, "http_headers", args, url, e)
    try:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": UA},
                                     follow_redirects=False, verify=False) as c:
            r = await c.get(url)
    except Exception as e:
        return _block(ctx, "http_headers", args, url, e)

    h = {k.lower(): v for k, v in r.headers.items()}
    present = {name: h.get(name) for name in SECURITY_HEADERS if name in h}
    missing = [name for name in SECURITY_HEADERS if name not in h]
    cookies = []
    for sc in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
        cookies.append({
            "raw": sc.split(";")[0].split("=")[0],
            "secure": "secure" in sc.lower(),
            "httponly": "httponly" in sc.lower(),
            "samesite": (re.search(r"(?i)samesite=(\w+)", sc) or [None, None])[1],
        })
    ctx.auditor.record("http_headers", args, url, "ok")
    return {"ok": True, "status": r.status_code, "server": h.get("server"),
            "security_headers_present": present, "security_headers_missing": missing,
            "cookies": cookies}


# ---- WAF detect --------------------------------------------------------------

async def waf_detect(ctx: ReconContext, url: str) -> dict[str, Any]:
    args = {"url": url}
    try:
        url = utils.valid_url(url)
        ctx.guard.assert_in_scope(url)
    except Exception as e:
        return _block(ctx, "waf_detect", args, url, e)
    res = await ctx.runner.run("waf_detect", ["wafw00f", "-a", url], timeout=120)
    found = re.findall(r"is behind (.+?)(?: WAF)?\.?$", res.raw_stdout, re.M)
    vendor = found[0].strip() if found else ("none detected"
             if re.search(r"No WAF detected", res.raw_stdout, re.I) else None)
    ctx.auditor.record("waf_detect", args, url, "ok", res.duration_s,
                       res.exit_code, res.evidence_file)
    return {"ok": True, "waf": vendor, "evidence_file": res.evidence_file}


# ---- TLS scan ----------------------------------------------------------------

async def tls_scan(ctx: ReconContext, host: str, port: int = 443) -> dict[str, Any]:
    args = {"host": host, "port": port}
    try:
        host = utils.valid_host(host)
        port = utils.clamp(int(port), 1, 65535)
        ctx.guard.assert_in_scope(host)
    except Exception as e:
        return _block(ctx, "tls_scan", args, host, e)

    from ..runner import have_binary
    cert_summary: dict[str, Any] = {}
    # Primary: certificate detail via a direct TLS handshake (no extra binary).
    try:
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        # getpeercert() with CERT_NONE returns {} — do a verified pass for fields.
        vctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=15) as s2:
                with vctx.wrap_socket(s2, server_hostname=host) as vs:
                    cert = vs.getpeercert() or cert
        except Exception:
            pass
        subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
        sans = [v for (_t, v) in cert.get("subjectAltName", [])] if cert else []
        not_after = cert.get("notAfter") if cert else None
        days_left = None
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        cert_summary = {
            "subject_cn": subject.get("commonName"), "issuer_cn": issuer.get("commonName"),
            "sans": sans, "valid_until": not_after, "days_to_expiry": days_left,
            "negotiated_protocol": proto,
        }
    except Exception as e:
        cert_summary = {"error": str(e)}

    # Supplement: sslscan for protocol/cipher weaknesses if available.
    evidence = None
    weak = []
    protocols = []
    if have_binary("sslscan"):
        res = await ctx.runner.run("tls_scan", ["sslscan", "--no-colour", f"{host}:{port}"], timeout=120)
        evidence = res.evidence_file
        for proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
            if re.search(rf"{re.escape(proto)}\s+enabled", res.raw_stdout):
                protocols.append(proto)
        if any(p in protocols for p in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]):
            weak.append("legacy TLS/SSL protocol enabled")
        if re.search(r"(?i)(RC4|DES|NULL|EXPORT|MD5)", res.raw_stdout):
            weak.append("weak cipher advertised")

    ctx.auditor.record("tls_scan", args, host, "ok", evidence_file=evidence)
    return {"ok": True, "certificate": cert_summary, "protocols": protocols,
            "weaknesses": weak, "evidence_file": evidence}


# ---- tech fingerprint --------------------------------------------------------

async def tech_fingerprint(ctx: ReconContext, url: str) -> dict[str, Any]:
    args = {"url": url}
    try:
        url = utils.valid_url(url)
        ctx.guard.assert_in_scope(url)
    except Exception as e:
        return _block(ctx, "tech_fingerprint", args, url, e)
    list_file = ctx.config.evidence_path("tech_fingerprint") / "target.txt"
    list_file.write_text(url)
    res = await ctx.runner.run(
        "tech_fingerprint",
        ["httpx", "-silent", "-json", "-tech-detect", "-l", str(list_file)], timeout=120)
    tech = []
    for line in res.raw_stdout.splitlines():
        try:
            tech = json.loads(line).get("tech", []) or tech
        except (json.JSONDecodeError, ValueError):
            continue
    ctx.auditor.record("tech_fingerprint", args, url, "ok", res.duration_s,
                       res.exit_code, res.evidence_file)
    return {"ok": True, "technologies": tech, "evidence_file": res.evidence_file}


# ---- favicon hash ------------------------------------------------------------

async def favicon_hash(ctx: ReconContext, url: str) -> dict[str, Any]:
    args = {"url": url}
    try:
        url = utils.valid_url(url)
        ctx.guard.assert_in_scope(url)
    except Exception as e:
        return _block(ctx, "favicon_hash", args, url, e)
    try:
        import base64
        import mmh3  # type: ignore
    except ImportError:
        return _block(ctx, "favicon_hash", args, url, ValidationError("pip install mmh3"))
    fav = url.rstrip("/") + "/favicon.ico"
    try:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": UA}, verify=False) as c:
            r = await c.get(fav)
            r.raise_for_status()
            b64 = base64.encodebytes(r.content)
            h = mmh3.hash(b64)
    except Exception as e:
        return _block(ctx, "favicon_hash", args, fav, e)
    ctx.auditor.record("favicon_hash", args, fav, "ok")
    return {"ok": True, "favicon_hash": h,
            "shodan_query": f"http.favicon.hash:{h}",
            "fofa_query": f'icon_hash="{h}"'}


# ---- subdomain takeover detection -------------------------------------------

# Minimal fingerprint set — CNAME target substring -> service name. DETECT ONLY.
TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3", "github.io": "GitHub Pages",
    "herokudns.com": "Heroku", "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure", "cloudapp.net": "Azure",
    "ghost.io": "Ghost", "wordpress.com": "WordPress",
    "pantheonsite.io": "Pantheon", "fastly.net": "Fastly",
    "zendesk.com": "Zendesk", "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "readthedocs.io": "ReadTheDocs", "netlify.app": "Netlify",
}


async def takeover_check(ctx: ReconContext, subdomains: list[str]) -> dict[str, Any]:
    args = {"subdomains": subdomains}
    candidates = []
    checked = []
    for sub in subdomains:
        try:
            sub = utils.valid_domain(sub)
            ctx.guard.assert_in_scope(sub)
        except Exception:
            continue
        checked.append(sub)
        res = await ctx.runner.run("takeover_check", ["dig", "+short", "CNAME", sub])
        cname = res.raw_stdout.strip().splitlines()
        cname = cname[0].rstrip(".") if cname and not cname[0].startswith(("$", "#")) else None
        if not cname:
            continue
        for frag, svc in TAKEOVER_FINGERPRINTS.items():
            if frag in cname:
                candidates.append({"subdomain": sub, "cname": cname, "service": svc,
                                   "note": "DETECT ONLY — manually verify; do NOT claim"})
                break
    ctx.auditor.record("takeover_check", args, ",".join(checked[:5]), "ok",
                       note=f"{len(candidates)} candidates")
    return {"ok": True, "candidates": candidates}
