"""PASSIVE lane — no packets to the target's live services (OSINT + DNS + public APIs).

These never need RoE active authorization, but targets are still scope-checked and
every call is audited.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..context import ReconContext
from ..scope import ScopeError
from . import utils
from .utils import ValidationError

UA = "redpent-tools/0.1 (authorized-assessment)"


# ---- helpers -----------------------------------------------------------------

def _audit_block(ctx: ReconContext, tool: str, args: dict, target: str | None, exc: Exception) -> dict:
    status = "blocked" if isinstance(exc, (ScopeError, ValidationError)) else "error"
    ctx.auditor.record(tool, args, target, status, note=str(exc))
    return {"ok": False, "status": status, "error": str(exc)}


async def _dig(ctx: ReconContext, name: str, rtype: str, tool: str) -> list[str]:
    """Run dig +noall +answer and return the answer lines."""
    res = await ctx.runner.run(tool, ["dig", "+noall", "+answer", name, rtype])
    lines = [l for l in res.raw_stdout.splitlines() if l and not l.startswith(("$", "#"))]
    return lines


# ---- WHOIS -------------------------------------------------------------------

async def whois_lookup(ctx: ReconContext, domain: str) -> dict[str, Any]:
    args = {"domain": domain}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "whois_lookup", args, domain, e)

    res = await ctx.runner.run("whois_lookup", ["whois", domain], timeout=60)
    text = res.raw_stdout

    def grab(pat):
        m = re.search(pat, text, re.I)
        return m.group(1).strip() if m else None

    name_servers = sorted(set(re.findall(r"(?i)name server:\s*(\S+)", text)))
    status_flags = sorted(set(re.findall(r"(?i)^\s*status:\s*(\S+)", text, re.M)))
    expiry = grab(r"(?i)(?:registry expiry date|expiration date|expires on|expiry date):\s*(.+)")
    summary = {
        "registrar": grab(r"(?i)registrar:\s*(.+)"),
        "iana_id": grab(r"(?i)registrar iana id:\s*(\d+)"),
        "created": grab(r"(?i)(?:creation date|created on|created):\s*(.+)"),
        "updated": grab(r"(?i)(?:updated date|last updated):\s*(.+)"),
        "expires": expiry,
        "name_servers": name_servers,
        "status_flags": status_flags,
        "abuse_email": grab(r"(?i)(?:registrar abuse contact email|abuse.*email):\s*(\S+@\S+)"),
        "flags": [],
    }
    if not any("clienttransferprohibited" in s.lower() for s in status_flags):
        summary["flags"].append("MISSING clientTransferProhibited (domain-hijack hardening)")
    ctx.auditor.record("whois_lookup", args, domain, "ok", res.duration_s,
                       res.exit_code, res.evidence_file)
    return {"ok": True, "summary": summary, "evidence_file": res.evidence_file}


# ---- DNS ---------------------------------------------------------------------

async def dns_lookup(ctx: ReconContext, domain: str,
                     record_types: list[str] | None = None) -> dict[str, Any]:
    record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"]
    args = {"domain": domain, "record_types": record_types}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "dns_lookup", args, domain, e)

    records: dict[str, list[str]] = {}
    for rt in record_types:
        if not re.match(r"^[A-Z]{1,10}$", rt.upper()):
            continue
        records[rt.upper()] = await _dig(ctx, domain, rt.upper(), "dns_lookup")

    saas_tokens = [t for t in records.get("TXT", [])
                   if re.search(r"(?i)(verification|site-verification|=)", t)]
    from ..scope import _ip_in_any, CLOUDFLARE_V4  # local import to avoid cycle
    a_ips = re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", " ".join(records.get("A", [])))
    cloudflare = [ip for ip in a_ips if _ip_in_any(ip, CLOUDFLARE_V4)]

    ctx.auditor.record("dns_lookup", args, domain, "ok")
    return {
        "ok": True,
        "records": records,
        "cloudflare_fronted_ips": cloudflare,
        "saas_verification_tokens": saas_tokens,
    }


# ---- Email auth (SPF / DKIM / DMARC) ----------------------------------------

async def email_auth_check(ctx: ReconContext, domain: str,
                           dkim_selectors: list[str] | None = None) -> dict[str, Any]:
    dkim_selectors = dkim_selectors or ["google", "default", "selector1", "selector2"]
    args = {"domain": domain, "dkim_selectors": dkim_selectors}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "email_auth_check", args, domain, e)

    txt = await _dig(ctx, domain, "TXT", "email_auth_check")
    spf = next((t for t in txt if "v=spf1" in t.lower()), None)
    spf_info = None
    if spf:
        includes = re.findall(r"include:(\S+)", spf)
        lookups = len(re.findall(r"(?:include:|a:|mx:|ptr:|exists:|redirect=)", spf))
        all_q = re.search(r"([-~?+])all", spf)
        spf_info = {
            "record": spf.strip('"'),
            "includes": includes,
            "lookup_count": lookups,
            "permerror_risk": lookups > 10,
            "all_qualifier": all_q.group(1) if all_q else None,
        }

    dkim = {}
    for sel in dkim_selectors:
        recs = await _dig(ctx, f"{sel}._domainkey.{domain}", "TXT", "email_auth_check")
        joined = " ".join(recs)
        if "v=dkim1" in joined.lower() or "p=" in joined.lower():
            ktype = (re.search(r"k=(\w+)", joined) or [None, "rsa"])[1]
            p = re.search(r"p=([A-Za-z0-9+/=]+)", joined)
            bits = int(len(p.group(1)) * 6 / 8 * 8) if p else 0  # rough
            dkim[sel] = {"found": True, "key_type": ktype, "approx_key_bits": bits}
        else:
            dkim[sel] = {"found": False}

    dmarc_txt = await _dig(ctx, f"_dmarc.{domain}", "TXT", "email_auth_check")
    dmarc_rec = next((t for t in dmarc_txt if "v=dmarc1" in t.lower()), None)
    dmarc_info = None
    if dmarc_rec:
        def tag(t):
            m = re.search(rf"{t}=([^;\"]+)", dmarc_rec)
            return m.group(1).strip() if m else None
        p = (tag("p") or "none").lower()
        pct = tag("pct") or "100"
        rating = "weak" if p == "none" else ("medium" if p == "quarantine" else "strong")
        if p != "none" and pct and int(pct) < 100:
            rating = "medium"
        dmarc_info = {
            "record": dmarc_rec.strip('"'), "p": p, "sp": tag("sp"), "pct": pct,
            "rua": tag("rua"), "ruf": tag("ruf"), "adkim": tag("adkim"),
            "aspf": tag("aspf"), "rating": rating,
        }

    ctx.auditor.record("email_auth_check", args, domain, "ok")
    return {"ok": True, "spf": spf_info, "dkim": dkim, "dmarc": dmarc_info}


# ---- Reverse DNS -------------------------------------------------------------

async def reverse_dns(ctx: ReconContext, ips: list[str]) -> dict[str, Any]:
    args = {"ips": ips}
    out: dict[str, str | None] = {}
    checked = []
    for ip in ips:
        try:
            ip = utils.valid_ip(ip)
            ctx.guard.assert_in_scope(ip)
        except Exception:
            out[ip] = "(out of scope / invalid — skipped)"
            continue
        res = await ctx.runner.run("reverse_dns", ["dig", "+short", "-x", ip])
        ptr = res.raw_stdout.strip().splitlines()
        out[ip] = ptr[0] if ptr and not ptr[0].startswith(("$", "#")) else None
        checked.append(ip)
    ctx.auditor.record("reverse_dns", args, ",".join(checked), "ok")
    return {"ok": True, "ptr": out}


# ---- crt.sh ------------------------------------------------------------------

async def crtsh_subdomains(ctx: ReconContext, domain: str) -> dict[str, Any]:
    args = {"domain": domain}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "crtsh_subdomains", args, domain, e)
    hosts: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=60, headers={"User-Agent": UA}) as c:
            r = await c.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            r.raise_for_status()
            for row in r.json():
                for n in (row.get("name_value") or "").splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain):
                        hosts.add(n)
    except Exception as e:
        return _audit_block(ctx, "crtsh_subdomains", args, domain, e)
    result = sorted(hosts)
    ctx.auditor.record("crtsh_subdomains", args, domain, "ok", note=f"{len(result)} hosts")
    return {"ok": True, "count": len(result), "subdomains": result}


# ---- subfinder ---------------------------------------------------------------

async def subfinder_enum(ctx: ReconContext, domain: str, all_sources: bool = True) -> dict[str, Any]:
    args = {"domain": domain, "all_sources": all_sources}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "subfinder_enum", args, domain, e)
    cmd = ["subfinder", "-silent", "-d", domain]
    if all_sources:
        cmd.append("-all")
    res = await ctx.runner.run("subfinder_enum", cmd, timeout=600)
    subs = utils.dedupe(res.raw_stdout.splitlines())
    ctx.auditor.record("subfinder_enum", args, domain, "ok", res.duration_s,
                       res.exit_code, res.evidence_file, f"{len(subs)} subs")
    return {"ok": True, "count": len(subs), "subdomains": subs, "evidence_file": res.evidence_file}


# ---- theHarvester ------------------------------------------------------------

async def harvester_enum(ctx: ReconContext, domain: str,
                         sources: str = "crtsh,bing,dnsdumpster") -> dict[str, Any]:
    args = {"domain": domain, "sources": sources}
    try:
        domain = utils.valid_domain(domain)
        if not re.match(r"^[a-z0-9,_-]+$", sources):
            raise ValidationError("invalid sources list")
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "harvester_enum", args, domain, e)
    res = await ctx.runner.run(
        "harvester_enum",
        ["theHarvester", "-d", domain, "-b", sources], timeout=600)
    text = res.raw_stdout
    hosts = utils.dedupe(re.findall(rf"([a-z0-9.-]+\.{re.escape(domain)})", text, re.I))
    ips = utils.dedupe(re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", text))
    emails = utils.dedupe(re.findall(r"[\w.+-]+@[\w.-]+", text))
    if not ctx.config.scope.allow_email_output:
        emails = [re.sub(r"^(.).*(@.*)$", r"\1***\2", e) for e in emails]
    ctx.auditor.record("harvester_enum", args, domain, "ok", res.duration_s,
                       res.exit_code, res.evidence_file)
    return {"ok": True, "hosts": hosts, "ips": ips, "emails": emails,
            "evidence_file": res.evidence_file}


# ---- wayback -----------------------------------------------------------------

async def wayback_urls(ctx: ReconContext, domain: str, filter: str = "all") -> dict[str, Any]:
    args = {"domain": domain, "filter": filter}
    try:
        domain = utils.valid_domain(domain)
        ctx.guard.assert_in_scope(domain)
    except Exception as e:
        return _audit_block(ctx, "wayback_urls", args, domain, e)

    urls: list[str] = []
    # Prefer the CLI if present; otherwise fall back to the Wayback CDX API.
    from ..runner import have_binary
    if have_binary("waybackurls"):
        res = await ctx.runner.run("wayback_urls", ["waybackurls", domain], timeout=300)
        urls = res.raw_stdout.splitlines()
        evidence = res.evidence_file
    else:
        try:
            async with httpx.AsyncClient(timeout=120, headers={"User-Agent": UA}) as c:
                r = await c.get("https://web.archive.org/cdx/search/cdx",
                                params={"url": f"*.{domain}/*", "output": "text",
                                        "fl": "original", "collapse": "urlkey"})
                r.raise_for_status()
                urls = r.text.splitlines()
        except Exception as e:
            return _audit_block(ctx, "wayback_urls", args, domain, e)
        evidence = None

    urls = utils.dedupe(urls)
    if filter == "params":
        urls = [u for u in urls if "?" in u and "=" in u]
    elif filter == "api":
        urls = [u for u in urls if re.search(r"/api/|/v\d+/|\.json", u)]
    elif filter == "js":
        urls = [u for u in urls if u.lower().endswith(".js")]
    ctx.auditor.record("wayback_urls", args, domain, "ok", note=f"{len(urls)} urls")
    return {"ok": True, "count": len(urls), "urls": urls[:2000], "evidence_file": evidence}


# ---- Shodan / Censys (API, passive) -----------------------------------------

async def shodan_host(ctx: ReconContext, ip: str) -> dict[str, Any]:
    args = {"ip": ip}
    try:
        ip = utils.valid_ip(ip)
        ctx.guard.assert_in_scope(ip)
        if not ctx.config.shodan_api_key:
            raise ValidationError("SHODAN_API_KEY not set")
    except Exception as e:
        return _audit_block(ctx, "shodan_host", args, ip, e)
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.get(f"https://api.shodan.io/shodan/host/{ip}",
                            params={"key": ctx.config.shodan_api_key})
            r.raise_for_status()
            d = r.json()
    except Exception as e:
        return _audit_block(ctx, "shodan_host", args, ip, e)
    summary = {
        "ip": ip, "org": d.get("org"), "isp": d.get("isp"),
        "ports": sorted(d.get("ports", [])), "last_update": d.get("last_update"),
        "hostnames": d.get("hostnames", []),
        "products": sorted({s.get("product") for s in d.get("data", []) if s.get("product")}),
    }
    ctx.auditor.record("shodan_host", args, ip, "ok")
    return {"ok": True, "summary": summary}


async def shodan_search(ctx: ReconContext, query: str) -> dict[str, Any]:
    args = {"query": query}
    if not ctx.config.shodan_api_key:
        return _audit_block(ctx, "shodan_search", args, None, ValidationError("SHODAN_API_KEY not set"))
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.get("https://api.shodan.io/shodan/host/search",
                            params={"key": ctx.config.shodan_api_key, "query": query})
            r.raise_for_status()
            d = r.json()
    except Exception as e:
        return _audit_block(ctx, "shodan_search", args, None, e)
    matches = [{"ip": m.get("ip_str"), "port": m.get("port"),
                "org": m.get("org"), "product": m.get("product")}
               for m in d.get("matches", [])]
    ctx.auditor.record("shodan_search", args, None, "ok", note=query)
    return {"ok": True, "total": d.get("total"), "matches": matches[:100]}


async def censys_search(ctx: ReconContext, query: str) -> dict[str, Any]:
    args = {"query": query}
    if not (ctx.config.censys_api_id and ctx.config.censys_api_secret):
        return _audit_block(ctx, "censys_search", args, None,
                            ValidationError("CENSYS_API_ID / CENSYS_API_SECRET not set"))
    try:
        async with httpx.AsyncClient(
            timeout=60, auth=(ctx.config.censys_api_id, ctx.config.censys_api_secret)
        ) as c:
            r = await c.post("https://search.censys.io/api/v2/hosts/search",
                             json={"q": query, "per_page": 50})
            r.raise_for_status()
            d = r.json()
    except Exception as e:
        return _audit_block(ctx, "censys_search", args, None, e)
    hits = []
    for h in d.get("result", {}).get("hits", []):
        hits.append({"ip": h.get("ip"),
                     "services": [s.get("service_name") for s in h.get("services", [])],
                     "names": h.get("dns", {}).get("names", [])})
    ctx.auditor.record("censys_search", args, None, "ok", note=query)
    return {"ok": True, "count": len(hits), "hits": hits}
