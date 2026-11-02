"""redpent-tools FastMCP server.

Registers every SOP recon tool with its lane tag (PASSIVE / BOUNDARY / ACTIVE) in the
description so the model can see the risk level. A single shared ReconContext holds the
config, scope guard, auditor, and runner.

Run:
    python -m redpent_tools.server            # stdio (for Claude Desktop / Claude Code)
    python -m redpent_tools.server --http     # streamable HTTP on :8970
"""
from __future__ import annotations

import argparse
import json
import sys

from mcp.server.fastmcp import FastMCP

from .context import ReconContext
from .tools import active, boundary, passive, utility

mcp = FastMCP("redpent-tools")
CTX = ReconContext.create()

# =====================================================================
# PASSIVE lane
# =====================================================================

@mcp.tool()
async def whois_lookup(domain: str) -> dict:
    """[PASSIVE] WHOIS for a domain: registrar, dates, name servers, status flags,
    abuse email. Flags near expiry / missing clientTransferProhibited."""
    return await passive.whois_lookup(CTX, domain)


@mcp.tool()
async def dns_lookup(domain: str, record_types: list[str] | None = None) -> dict:
    """[PASSIVE] DNS records (A/AAAA/MX/NS/TXT/CNAME/CAA/SOA by default) with Cloudflare
    tagging and SaaS verification-token extraction."""
    return await passive.dns_lookup(CTX, domain, record_types)


@mcp.tool()
async def email_auth_check(domain: str, dkim_selectors: list[str] | None = None) -> dict:
    """[PASSIVE] SPF (includes + lookup count), DKIM per selector, and DMARC policy with
    a weak/medium/strong rating (SOP 3.13)."""
    return await passive.email_auth_check(CTX, domain, dkim_selectors)


@mcp.tool()
async def reverse_dns(ips: list[str]) -> dict:
    """[PASSIVE] Reverse DNS (PTR) for a list of in-scope IPs."""
    return await passive.reverse_dns(CTX, ips)


@mcp.tool()
async def crtsh_subdomains(domain: str) -> dict:
    """[PASSIVE] Subdomains from crt.sh certificate transparency logs."""
    return await passive.crtsh_subdomains(CTX, domain)


@mcp.tool()
async def subfinder_enum(domain: str, all_sources: bool = True) -> dict:
    """[PASSIVE] Subdomain enumeration via subfinder (passive sources)."""
    return await passive.subfinder_enum(CTX, domain, all_sources)


@mcp.tool()
async def harvester_enum(domain: str, sources: str = "crtsh,bing,dnsdumpster") -> dict:
    """[PASSIVE] theHarvester OSINT: hosts, IPs, emails (emails masked unless scope allows)."""
    return await passive.harvester_enum(CTX, domain, sources)


@mcp.tool()
async def wayback_urls(domain: str, filter: str = "all") -> dict:
    """[PASSIVE] Historical URLs from the Wayback Machine (filter: params|api|js|all)."""
    return await passive.wayback_urls(CTX, domain, filter)


@mcp.tool()
async def shodan_host(ip: str) -> dict:
    """[PASSIVE] Shodan host lookup (ports/products/org). Needs SHODAN_API_KEY."""
    return await passive.shodan_host(CTX, ip)


@mcp.tool()
async def shodan_search(query: str) -> dict:
    """[PASSIVE] Shodan search query. Needs SHODAN_API_KEY."""
    return await passive.shodan_search(CTX, query)


@mcp.tool()
async def censys_search(query: str) -> dict:
    """[PASSIVE] Censys hosts search. Needs CENSYS_API_ID / CENSYS_API_SECRET."""
    return await passive.censys_search(CTX, query)


# =====================================================================
# BOUNDARY lane (light touch, in-scope only)
# =====================================================================

@mcp.tool()
async def httpx_probe(hosts: list[str]) -> dict:
    """[BOUNDARY] Probe in-scope hosts: status, title, tech, redirect (rate-limited)."""
    return await boundary.httpx_probe(CTX, hosts)


@mcp.tool()
async def http_headers(url: str) -> dict:
    """[BOUNDARY] Fetch headers for an in-scope URL: server, security headers present/missing,
    cookie flags (Secure/HttpOnly/SameSite)."""
    return await boundary.http_headers(CTX, url)


@mcp.tool()
async def waf_detect(url: str) -> dict:
    """[BOUNDARY] WAF fingerprint via wafw00f."""
    return await boundary.waf_detect(CTX, url)


@mcp.tool()
async def tls_scan(host: str, port: int = 443) -> dict:
    """[BOUNDARY] TLS/cert inspection: subject, SANs, issuer, validity, protocols, weak ciphers."""
    return await boundary.tls_scan(CTX, host, port)


@mcp.tool()
async def tech_fingerprint(url: str) -> dict:
    """[BOUNDARY] Technology detection via httpx -tech-detect."""
    return await boundary.tech_fingerprint(CTX, url)


@mcp.tool()
async def favicon_hash(url: str) -> dict:
    """[BOUNDARY] mmh3 favicon hash + ready-made Shodan/FOFA pivot queries."""
    return await boundary.favicon_hash(CTX, url)


@mcp.tool()
async def takeover_check(subdomains: list[str]) -> dict:
    """[BOUNDARY] Subdomain-takeover detection (CNAME + fingerprint). DETECT ONLY — never claims."""
    return await boundary.takeover_check(CTX, subdomains)


# =====================================================================
# ACTIVE lane (GATED — requires active_allowed + window + confirm_authorized + engagement_id)
# =====================================================================

@mcp.tool()
async def nmap_scan(target: str, ports: str = "top-1000", version: bool = True,
                    default_scripts: bool = True, timing: int = 4,
                    confirm_authorized: bool = False, engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] nmap port/service/script scan. Requires confirm_authorized=true and a
    matching engagement_id, with scope.active_allowed and an open active_window."""
    return await active.nmap_scan(CTX, target, ports, version, default_scripts, timing,
                                  confirm_authorized, engagement_id)


@mcp.tool()
async def masscan_scan(ip: str, ports: str = "0-65535", rate: int = 1000,
                       confirm_authorized: bool = False, engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] masscan fast port sweep (rate-clamped; out_of_scope auto-excluded)."""
    return await active.masscan_scan(CTX, ip, ports, rate, confirm_authorized, engagement_id)


@mcp.tool()
async def ffuf_fuzz(url_with_FUZZ: str, wordlist: str, match_codes: str = "200,301,302,403",
                    filter_size: int | None = None, threads: int = 10,
                    confirm_authorized: bool = False, engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] ffuf content discovery. Wordlist must live in the allowed wordlists dir;
    auto soft-404 size detection; thread-clamped."""
    return await active.ffuf_fuzz(CTX, url_with_FUZZ, wordlist, match_codes, filter_size,
                                  threads, confirm_authorized, engagement_id)


@mcp.tool()
async def nikto_scan(url: str, tuning: str | None = None,
                     confirm_authorized: bool = False, engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] nikto web server scan. Findings flagged 'needs manual verification'."""
    return await active.nikto_scan(CTX, url, tuning, confirm_authorized, engagement_id)


@mcp.tool()
async def sqlmap_scan(url: str, data: str | None = None, level: int = 1, risk: int = 1,
                      cookie: str | None = None, confirm_authorized: bool = False,
                      engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] SQL-injection test via sqlmap (detection only: always --batch, never
    --os-shell/--sql-shell/--file-*). level 1-5 / risk 1-3 clamped to scope.limits."""
    return await active.sqlmap_scan(CTX, url, data, level, risk, cookie,
                                    confirm_authorized, engagement_id)


@mcp.tool()
async def commix_scan(url: str, data: str | None = None, level: int = 1,
                      cookie: str | None = None, confirm_authorized: bool = False,
                      engagement_id: str = "") -> dict:
    """[ACTIVE — GATED] Command-injection test via commix (detection only: always --batch, no
    --os-cmd/--os-shell). level 1-3 clamped to scope.limits."""
    return await active.commix_scan(CTX, url, data, level, cookie,
                                    confirm_authorized, engagement_id)


# =====================================================================
# UTILITY lane
# =====================================================================

@mcp.tool()
async def scope_check(target: str) -> dict:
    """[UTILITY] Is a target in scope? Returns in_scope + reason + resolved IPs + CDN tag."""
    return utility.scope_check(CTX, target)


@mcp.tool()
async def get_scope() -> dict:
    """[UTILITY] Current scope config (secrets omitted)."""
    return utility.get_scope(CTX)


@mcp.tool()
async def merge_assets(lists: list[list[str]]) -> dict:
    """[UTILITY] Deduplicate multiple subdomain lists into one master list (SOP 1.6)."""
    return utility.merge_assets(CTX, lists)


@mcp.tool()
async def session_log(note: str) -> dict:
    """[UTILITY] Append a note to the engagement SESSION.md + audit trail."""
    return utility.session_log(CTX, note)


@mcp.tool()
async def recon_report(engagement_id: str) -> dict:
    """[UTILITY] Build the SOP §4.3 recon report from saved evidence + audit trail."""
    return utility.recon_report(CTX, engagement_id)


# =====================================================================
# Resources
# =====================================================================

@mcp.resource("scope://current")
def scope_resource() -> str:
    return json.dumps(utility.get_scope(CTX), indent=2)


@mcp.resource("evidence://{engagement_id}/index")
def evidence_index(engagement_id: str) -> str:
    base = CTX.config.evidence_dir / engagement_id
    if not base.exists():
        return f"(no evidence for {engagement_id})"
    files = sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
    return "\n".join(files)


@mcp.resource("sop://checklist")
def sop_checklist() -> str:
    return (
        "redpent-tools — passive-first checklist\n"
        "1. WHOIS + DNS + email auth (SPF/DKIM/DMARC)\n"
        "2. Certificate transparency (crt.sh) + subfinder + theHarvester\n"
        "3. Merge assets -> master subdomain list\n"
        "4. Wayback URLs (params/api/js)\n"
        "5. Shodan/Censys passive host intel\n"
        "6. BOUNDARY: httpx probe, headers, WAF, TLS, tech, favicon pivots\n"
        "7. Subdomain takeover detection (DETECT ONLY)\n"
        "8. (ACTIVE, only if RoE allows) nmap/masscan/ffuf/nikto\n"
        "9. Rank attack surface\n"
        "10. recon_report -> SOP §4.3 deliverable\n"
    )


# =====================================================================
# Prompt template
# =====================================================================

@mcp.prompt()
def passive_recon_flow(domain: str) -> str:
    """Walk SOP steps 1-4 and 8-10 using ONLY passive/boundary tools, then recon_report."""
    return (
        f"Run authorized PASSIVE reconnaissance on {domain}. Use ONLY passive and boundary "
        f"tools (no nmap/masscan/ffuf/nikto). In order:\n"
        f"1. scope_check('{domain}') — confirm in scope before anything else.\n"
        f"2. whois_lookup, dns_lookup, email_auth_check on {domain}.\n"
        f"3. crtsh_subdomains + subfinder_enum + harvester_enum, then merge_assets.\n"
        f"4. httpx_probe the merged hosts; http_headers + tls_scan + waf_detect on the live ones.\n"
        f"5. wayback_urls(filter='params'); takeover_check on dangling CNAMEs.\n"
        f"6. recon_report('{CTX.config.engagement_id}').\n"
        f"Stop and report if any target is out of scope."
    )


# =====================================================================
# Entrypoint
# =====================================================================

def main() -> None:
    import os
    parser = argparse.ArgumentParser(description="redpent-tools MCP server")
    parser.add_argument("--http", action="store_true",
                        help="serve as a persistent streamable-HTTP MCP service")
    parser.add_argument("--host", default=os.environ.get("REDPENT_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("REDPENT_HTTP_PORT", "8971")))
    args = parser.parse_args()
    # REDPENT_HTTP=1 makes the HTTP service the default (so `redpent-tools` run as a
    # service needs no flags); stdio stays the default for an MCP client that spawns it.
    serve_http = args.http or os.environ.get("REDPENT_HTTP") == "1"
    if serve_http:
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        app = mcp.streamable_http_app()
        api_key = os.environ.get("REDPENT_API_KEY")
        if api_key:
            from .auth import ApiKeyMiddleware
            app = ApiKeyMiddleware(app, api_key)
            print("redpent-tools: API-key auth ENABLED (X-API-Key / Bearer required)",
                  file=sys.stderr)
        else:
            print("redpent-tools: no REDPENT_API_KEY set — HTTP service is UNAUTHENTICATED "
                  "(bind to 127.0.0.1 only). Set REDPENT_API_KEY to require a key.",
                  file=sys.stderr)
        print(f"redpent-tools: serving MCP over HTTP at http://{args.host}:{args.port}/mcp",
              file=sys.stderr)
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    else:
        mcp.run()


def keygen() -> None:
    """Console entry `redpent-tools-keygen`: print a fresh API key (rpk_…)."""
    from .auth import generate_key
    print(generate_key())


if __name__ == "__main__":
    main()
