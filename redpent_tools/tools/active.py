"""ACTIVE lane — intrusive scanning. GATED (safety rule 3).

Every tool here calls ctx.guard.assert_active_allowed(confirm_authorized, engagement_id)
BEFORE building a command, and clamps rate/threads/timing to scope.limits. Rejected
calls are audited as 'blocked' with the exact gate that failed.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ..context import ReconContext
from ..runner import HEAVY_TIMEOUT
from ..scope import ScopeError
from . import utils
from .utils import ValidationError

# NSE script categories we refuse unless scope.allow_intrusive_nse is true.
FORBIDDEN_NSE = {"brute", "dos", "intrusive", "exploit", "vuln"}


def _gate(ctx, tool, args, target, confirm_authorized, engagement_id):
    """Run scope + active-gate checks. Returns a ScopeDecision or raises/records block."""
    ctx.guard.assert_active_allowed(confirm_authorized, engagement_id)
    return ctx.guard.assert_scannable_ip(target)


def _block(ctx, tool, args, target, exc):
    status = "blocked" if isinstance(exc, (ScopeError, ValidationError)) else "error"
    ctx.auditor.record(tool, args, target, status, note=str(exc))
    return {"ok": False, "status": status, "error": str(exc)}


# ---- nmap --------------------------------------------------------------------

async def nmap_scan(ctx: ReconContext, target: str, ports: str = "top-1000",
                    version: bool = True, default_scripts: bool = True, timing: int = 4,
                    confirm_authorized: bool = False, engagement_id: str = "") -> dict[str, Any]:
    args = {"target": target, "ports": ports, "timing": timing,
            "confirm_authorized": confirm_authorized, "engagement_id": engagement_id}
    try:
        target = utils.valid_host(target)
        ports = utils.valid_ports(ports)
        _gate(ctx, "nmap_scan", args, target, confirm_authorized, engagement_id)
    except Exception as e:
        return _block(ctx, "nmap_scan", args, target, e)

    timing = utils.clamp(int(timing), 0, ctx.config.scope.limits.nmap_max_timing)
    xml_out = ctx.config.evidence_path("nmap_scan") / "scan.xml"
    cmd = ["nmap", "-Pn", f"-T{timing}", "-oX", str(xml_out)]
    if ports == "top-1000":
        cmd += ["--top-ports", "1000"]
    elif ports == "top-100":
        cmd += ["--top-ports", "100"]
    elif ports == "all":
        cmd += ["-p-"]
    else:
        cmd += ["-p", ports]
    if version:
        cmd.append("-sV")
    if default_scripts:
        # -sC = default scripts; they are not in the forbidden categories.
        cmd.append("-sC")
    cmd.append(target)

    res = await ctx.runner.run("nmap_scan", cmd, timeout=HEAVY_TIMEOUT)
    hosts = _parse_nmap_xml(xml_out) if xml_out.exists() else []
    ctx.auditor.record("nmap_scan", args, target, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "hosts": hosts, "evidence_file": res.evidence_file,
            "xml_file": str(xml_out)}


def _parse_nmap_xml(xml_path: Path) -> list[dict]:
    hosts = []
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return hosts
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None
        ports = []
        for p in host.findall(".//port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "state": state.get("state") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
        hosts.append({"ip": ip, "ports": [p for p in ports if p["state"] == "open"]})
    return hosts


# ---- masscan -----------------------------------------------------------------

async def masscan_scan(ctx: ReconContext, ip: str, ports: str = "0-65535",
                       rate: int = 1000, confirm_authorized: bool = False,
                       engagement_id: str = "") -> dict[str, Any]:
    args = {"ip": ip, "ports": ports, "rate": rate,
            "confirm_authorized": confirm_authorized, "engagement_id": engagement_id}
    try:
        ip = utils.valid_ip(ip)
        ports = utils.valid_ports(ports)
        if ports in ("top-1000", "top-100"):
            ports = "1-1000"  # masscan has no top-ports preset
        _gate(ctx, "masscan_scan", args, ip, confirm_authorized, engagement_id)
    except Exception as e:
        return _block(ctx, "masscan_scan", args, ip, e)

    rate = utils.clamp(int(rate), 1, ctx.config.scope.limits.masscan_max_rate)
    # Write an exclude file from out_of_scope CIDRs/IPs so masscan never strays.
    excl = ctx.config.evidence_path("masscan_scan") / "exclude.txt"
    oos = [o for o in ctx.config.scope.out_of_scope if _looks_like_ip_or_cidr(o)]
    excl.write_text("\n".join(oos) if oos else "255.255.255.255/32")
    json_out = ctx.config.evidence_path("masscan_scan") / "scan.json"
    cmd = ["masscan", ip, "-p", ports, "--rate", str(rate),
           "--excludefile", str(excl), "-oJ", str(json_out)]
    res = await ctx.runner.run("masscan_scan", cmd, timeout=HEAVY_TIMEOUT)
    open_ports = _parse_masscan_json(json_out) if json_out.exists() else []
    ctx.auditor.record("masscan_scan", args, ip, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "open_ports": open_ports, "rate_used": rate,
            "evidence_file": res.evidence_file}


def _parse_masscan_json(json_out: Path) -> list[dict]:
    """masscan -oJ emits a JSON array of records (sometimes with a trailing comma).
    Fall back to line-by-line object parsing if the whole-file load fails."""
    txt = json_out.read_text().strip()
    rows: list = []
    try:
        data = json.loads(txt)
        rows = data if isinstance(data, list) else [data]
    except (json.JSONDecodeError, ValueError):
        for line in txt.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for p in row.get("ports", []):
            out.append({"ip": row.get("ip"), "port": p.get("port"), "proto": p.get("proto")})
    return out


def _looks_like_ip_or_cidr(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


# ---- ffuf --------------------------------------------------------------------

async def ffuf_fuzz(ctx: ReconContext, url_with_FUZZ: str, wordlist: str,
                    match_codes: str = "200,301,302,403", filter_size: int | None = None,
                    threads: int = 10, confirm_authorized: bool = False,
                    engagement_id: str = "") -> dict[str, Any]:
    args = {"url": url_with_FUZZ, "wordlist": wordlist, "match_codes": match_codes,
            "threads": threads, "confirm_authorized": confirm_authorized,
            "engagement_id": engagement_id}
    try:
        if "FUZZ" not in url_with_FUZZ:
            raise ValidationError("url must contain the FUZZ keyword")
        url = utils.valid_url(url_with_FUZZ.replace("FUZZ", "FUZZPLACEHOLDER")).replace(
            "FUZZPLACEHOLDER", "FUZZ")
        wl = utils.valid_wordlist(wordlist, ctx.config.wordlists_dir)
        if not re.match(r"^\d{3}(,\d{3})*$", match_codes):
            raise ValidationError("match_codes must be comma-separated HTTP codes")
        _gate(ctx, "ffuf_fuzz", args, url, confirm_authorized, engagement_id)
    except Exception as e:
        return _block(ctx, "ffuf_fuzz", args, url_with_FUZZ, e)

    threads = utils.clamp(int(threads), 1, ctx.config.scope.limits.ffuf_max_threads)
    json_out = ctx.config.evidence_path("ffuf_fuzz") / "ffuf.json"
    cmd = ["ffuf", "-u", url, "-w", str(wl), "-mc", match_codes,
           "-t", str(threads), "-of", "json", "-o", str(json_out), "-s"]

    # Auto soft-404 detection: probe 3 random paths, apply -fs if sizes agree.
    if filter_size is None:
        filter_size = await _detect_soft404(ctx, url)
    if filter_size:
        cmd += ["-fs", str(filter_size)]

    res = await ctx.runner.run("ffuf_fuzz", cmd, timeout=HEAVY_TIMEOUT)
    results = []
    if json_out.exists():
        try:
            for r in json.loads(json_out.read_text()).get("results", []):
                results.append({"path": r.get("input", {}).get("FUZZ"),
                                "status": r.get("status"), "size": r.get("length"),
                                "words": r.get("words"), "lines": r.get("lines")})
        except (json.JSONDecodeError, ValueError):
            pass
    ctx.auditor.record("ffuf_fuzz", args, url, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "results": results, "soft404_filter_size": filter_size,
            "evidence_file": res.evidence_file}


async def _detect_soft404(ctx: ReconContext, url: str) -> int | None:
    """GET 3 random unlikely paths; if their body sizes match, that's the soft-404 size."""
    import secrets
    import httpx
    base = url.replace("FUZZ", "")
    sizes = []
    try:
        async with httpx.AsyncClient(timeout=20, verify=False,
                                     headers={"User-Agent": UA_FFUF}) as c:
            for _ in range(3):
                rnd = secrets.token_hex(8)
                r = await c.get(base.rstrip("/") + "/" + rnd)
                sizes.append(len(r.content))
    except Exception:
        return None
    if len(set(sizes)) == 1 and sizes[0] > 0:
        return sizes[0]
    return None


UA_FFUF = "redpent-tools/0.1 (authorized-assessment)"


# ---- nikto -------------------------------------------------------------------

async def nikto_scan(ctx: ReconContext, url: str, tuning: str | None = None,
                     confirm_authorized: bool = False, engagement_id: str = "") -> dict[str, Any]:
    args = {"url": url, "tuning": tuning, "confirm_authorized": confirm_authorized,
            "engagement_id": engagement_id}
    try:
        url = utils.valid_url(url)
        if tuning is not None and not re.match(r"^[0-9x]+$", tuning):
            raise ValidationError("tuning must be nikto digits like '1234' or 'x'")
        _gate(ctx, "nikto_scan", args, url, confirm_authorized, engagement_id)
    except Exception as e:
        return _block(ctx, "nikto_scan", args, url, e)

    cmd = ["nikto", "-host", url, "-ask", "no"]
    if tuning:
        cmd += ["-Tuning", tuning]
    res = await ctx.runner.run("nikto_scan", cmd, timeout=HEAVY_TIMEOUT)
    findings = []
    for line in res.raw_stdout.splitlines():
        if line.strip().startswith("+") and "Target" not in line:
            findings.append({"finding": line.strip().lstrip("+ ").strip(),
                             "note": "needs manual verification"})
    ctx.auditor.record("nikto_scan", args, url, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "findings": findings, "evidence_file": res.evidence_file}


# ---- sqlmap (SQL injection) --------------------------------------------------

async def sqlmap_scan(ctx: ReconContext, url: str, data: str | None = None,
                      level: int = 1, risk: int = 1, cookie: str | None = None,
                      confirm_authorized: bool = False, engagement_id: str = "") -> dict[str, Any]:
    """SQL-injection detection/exploitation via sqlmap. GATED + scope-checked. We build a
    fixed, safe argv (always --batch, never --os-shell/--sql-shell/--file-*/--os-pwn), so
    no OS/file takeover flag can be injected; it detects and dumps-nothing by default."""
    args = {"url": url, "has_data": bool(data), "level": level, "risk": risk,
            "confirm_authorized": confirm_authorized, "engagement_id": engagement_id}
    try:
        url = utils.valid_url(url)
        _gate(ctx, "sqlmap_scan", args, url, confirm_authorized, engagement_id)
        if data is not None and any(c in data for c in ["\n", "`", "$("]):
            raise ValidationError("illegal characters in data")
        if cookie is not None and any(c in cookie for c in ["\n", "`", "$("]):
            raise ValidationError("illegal characters in cookie")
    except Exception as e:
        return _block(ctx, "sqlmap_scan", args, url, e)

    level = utils.clamp(int(level), 1, ctx.config.scope.limits.sqlmap_max_level)
    risk = utils.clamp(int(risk), 1, ctx.config.scope.limits.sqlmap_max_risk)
    out_dir = ctx.config.evidence_path("sqlmap_scan")
    cmd = ["sqlmap", "-u", url, "--batch", "--disable-coloring",
           "--level", str(level), "--risk", str(risk),
           "--output-dir", str(out_dir)]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    res = await ctx.runner.run("sqlmap_scan", cmd, timeout=HEAVY_TIMEOUT)
    txt = res.raw_stdout
    injectable = bool(re.search(r"(?i)is vulnerable|identified the following injection|"
                                r"appears to be .* injectable", txt))
    params = re.findall(r"(?i)Parameter: (\S+)", txt)
    dbms = (re.search(r"(?i)back-end DBMS: (.+)", txt) or [None, None])[1]
    ctx.auditor.record("sqlmap_scan", args, url, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "injectable": injectable, "parameters": utils.dedupe(params),
            "dbms": dbms.strip() if dbms else None, "level": level, "risk": risk,
            "evidence_file": res.evidence_file,
            "note": "detection only — no data dumped / no shell; confirm impact manually"}


# ---- commix (command injection) ----------------------------------------------

async def commix_scan(ctx: ReconContext, url: str, data: str | None = None,
                      level: int = 1, cookie: str | None = None,
                      confirm_authorized: bool = False, engagement_id: str = "") -> dict[str, Any]:
    """Command-injection detection via commix. GATED + scope-checked. Fixed safe argv
    (--batch, no --os-cmd/--os-shell/reverse-shell flags), detection only."""
    args = {"url": url, "has_data": bool(data), "level": level,
            "confirm_authorized": confirm_authorized, "engagement_id": engagement_id}
    try:
        url = utils.valid_url(url)
        _gate(ctx, "commix_scan", args, url, confirm_authorized, engagement_id)
        if data is not None and any(c in data for c in ["\n", "`", "$("]):
            raise ValidationError("illegal characters in data")
        if cookie is not None and any(c in cookie for c in ["\n", "`", "$("]):
            raise ValidationError("illegal characters in cookie")
    except Exception as e:
        return _block(ctx, "commix_scan", args, url, e)

    level = utils.clamp(int(level), 1, ctx.config.scope.limits.commix_max_level)
    out_dir = ctx.config.evidence_path("commix_scan")
    cmd = ["commix", "--url", url, "--batch", "--level", str(level),
           "--output-dir", str(out_dir)]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    res = await ctx.runner.run("commix_scan", cmd, timeout=HEAVY_TIMEOUT)
    txt = res.raw_stdout
    injectable = bool(re.search(r"(?i)is vulnerable to|seems to be injectable|"
                                r"the .* parameter is vulnerable", txt))
    technique = (re.search(r"(?i)Technique: (.+)", txt) or [None, None])[1]
    ctx.auditor.record("commix_scan", args, url, "ok" if res.ok else "error",
                       res.duration_s, res.exit_code, res.evidence_file)
    return {"ok": res.ok, "injectable": injectable,
            "technique": technique.strip() if technique else None, "level": level,
            "evidence_file": res.evidence_file,
            "note": "detection only — no command shell spawned; confirm impact manually"}
