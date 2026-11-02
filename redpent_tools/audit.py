"""Audit trail + secret masking.

Every tool invocation (allowed, blocked, or errored) is recorded here:
  * one JSON object per line in evidence/<eid>/audit.jsonl
  * one human-readable line appended to evidence/<eid>/SESSION.md
This is the "add every run to MCP" requirement — nothing runs without a record.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .config import Config, now_utc

# Patterns for secrets that tools sometimes echo back. Masked before returning text
# to the model AND before writing evidence summaries.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|token|secret|authorization|bearer)\b\s*[:=]\s*([A-Za-z0-9._\-]{8,})"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access key id
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),                   # GitHub PAT
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),          # Slack token
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),        # private keys
]


def mask_secrets(text: str) -> str:
    if not text:
        return text
    masked = text
    masked = _SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}: ***REDACTED***", masked)
    for pat in _SECRET_PATTERNS[1:]:
        masked = pat.sub("***REDACTED***", masked)
    return masked


class Auditor:
    def __init__(self, config: Config):
        self.cfg = config

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        target: str | None,
        status: str,
        duration_s: float = 0.0,
        exit_code: int | None = None,
        evidence_file: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        entry = {
            "ts": now_utc().isoformat(),
            "engagement_id": self.cfg.engagement_id,
            "tester": self.cfg.scope.tester,
            "tool": tool,
            "lane": _LANE.get(tool, "utility"),
            "target": target,
            "args": _safe_args(args),
            "status": status,            # allowed | blocked | error | ok
            "duration_s": round(duration_s, 3),
            "exit_code": exit_code,
            "evidence_file": evidence_file,
            "note": mask_secrets(note) if note else None,
        }
        # JSONL line
        with self.cfg.audit_log().open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
        # SESSION.md one-liner
        line = (
            f"- {entry['ts']} | {tool} | {status} | target={target} "
            f"| exit={exit_code} | {evidence_file or ''}"
        )
        if note:
            line += f" | {mask_secrets(note)[:160]}"
        with self.cfg.session_md().open("a") as fh:
            fh.write(line + "\n")
        return entry


def _safe_args(args: dict[str, Any]) -> dict[str, Any]:
    """Drop obvious secret-bearing kwargs from the audit args echo."""
    out = {}
    for k, v in args.items():
        if any(s in k.lower() for s in ("key", "secret", "token", "password")):
            out[k] = "***"
        else:
            out[k] = v
    return out


# Lane tags used in audit entries and tool descriptions.
_LANE = {
    "whois_lookup": "passive", "dns_lookup": "passive", "email_auth_check": "passive",
    "reverse_dns": "passive", "crtsh_subdomains": "passive", "subfinder_enum": "passive",
    "harvester_enum": "passive", "wayback_urls": "passive", "shodan_host": "passive",
    "shodan_search": "passive", "censys_search": "passive",
    "httpx_probe": "boundary", "http_headers": "boundary", "waf_detect": "boundary",
    "tls_scan": "boundary", "tech_fingerprint": "boundary", "favicon_hash": "boundary",
    "takeover_check": "boundary",
    "nmap_scan": "active", "masscan_scan": "active", "ffuf_fuzz": "active",
    "nikto_scan": "active", "sqlmap_scan": "active", "commix_scan": "active",
}
