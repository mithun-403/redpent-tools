"""Configuration loading: scope.yaml + environment variables.

Everything that controls safety lives in scope.yaml. Secrets live in env vars and
are NEVER written to evidence or returned to the model.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


# ---- Defaults (used when a key is absent from scope.yaml) --------------------

DEFAULT_LIMITS = {
    "masscan_max_rate": 1000,
    "ffuf_max_threads": 10,
    "nmap_max_timing": 4,
    # Injection tools (sqlmap/commix): conservative caps; raise in scope.yaml if RoE allows.
    "sqlmap_max_level": 3,   # sqlmap --level 1..5
    "sqlmap_max_risk": 2,    # sqlmap --risk  1..3
    "commix_max_level": 2,   # commix --level 1..3
}


def _env_path(var: str, default: str) -> Path:
    return Path(os.environ.get(var, default)).expanduser().resolve()


@dataclass
class Limits:
    masscan_max_rate: int = 1000
    ffuf_max_threads: int = 10
    nmap_max_timing: int = 4
    sqlmap_max_level: int = 3
    sqlmap_max_risk: int = 2
    commix_max_level: int = 2


@dataclass
class Scope:
    """Parsed scope.yaml. The authorization logic lives in scope.py; this is data."""

    engagement_id: str = "UNSET"
    roe_reference: str = ""
    tester: str = ""
    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_cidrs: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    active_allowed: bool = False
    active_window: dict[str, str] = field(default_factory=dict)
    limits: Limits = field(default_factory=Limits)
    allow_intrusive_nse: bool = False  # separate gate for brute/dos/intrusive/exploit/vuln
    allow_email_output: bool = False   # unmask harvested emails only if true
    configured: bool = True            # False when scope.yaml is absent (safe-deny default)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    scope: Scope
    scope_file: Path
    evidence_dir: Path
    wordlists_dir: Path
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None

    # Convenience passthroughs ------------------------------------------------
    @property
    def engagement_id(self) -> str:
        return self.scope.engagement_id

    def evidence_path(self, tool: str) -> Path:
        """Directory for a tool's raw output under this engagement."""
        p = self.evidence_dir / self.scope.engagement_id / tool
        p.mkdir(parents=True, exist_ok=True)
        return p

    def session_md(self) -> Path:
        p = self.evidence_dir / self.scope.engagement_id
        p.mkdir(parents=True, exist_ok=True)
        return p / "SESSION.md"

    def audit_log(self) -> Path:
        p = self.evidence_dir / self.scope.engagement_id
        p.mkdir(parents=True, exist_ok=True)
        return p / "audit.jsonl"


def load_scope(scope_file: Path) -> Scope:
    if not scope_file.exists():
        # Don't crash: a missing scope must still let the MCP server START so clients
        # can DISCOVER tools. We return an UNCONFIGURED scope with nothing in scope, so
        # every target-bearing tool safely denies until a real scope.yaml is provided.
        # A warning goes to stderr (stdout is reserved for the JSON-RPC stream).
        import sys
        print(f"redpent-tools: WARNING scope file not found ({scope_file}); starting "
              f"UNCONFIGURED — all targets will be denied until REDPENT_SCOPE_FILE points "
              f"to a valid scope.yaml. Copy scope.example.yaml to scope.yaml.",
              file=sys.stderr)
        return Scope(engagement_id="UNCONFIGURED", configured=False,
                     raw={"_missing": str(scope_file)})
    data = yaml.safe_load(scope_file.read_text()) or {}
    limits_raw = {**DEFAULT_LIMITS, **(data.get("limits") or {})}
    return Scope(
        engagement_id=str(data.get("engagement_id", "UNSET")),
        roe_reference=str(data.get("roe_reference", "")),
        tester=str(data.get("tester", "")),
        in_scope_domains=list(data.get("in_scope_domains") or []),
        in_scope_cidrs=list(data.get("in_scope_cidrs") or []),
        out_of_scope=list(data.get("out_of_scope") or []),
        active_allowed=bool(data.get("active_allowed", False)),
        active_window=dict(data.get("active_window") or {}),
        limits=Limits(**limits_raw),
        allow_intrusive_nse=bool(data.get("allow_intrusive_nse", False)),
        allow_email_output=bool(data.get("allow_email_output", False)),
        raw=data,
    )


def load_config() -> Config:
    scope_file = _env_path("REDPENT_SCOPE_FILE", "scope.yaml")
    evidence_dir = _env_path("REDPENT_EVIDENCE_DIR", "evidence")
    wordlists_dir = _env_path("REDPENT_WORDLISTS_DIR", "wordlists")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    return Config(
        scope=load_scope(scope_file),
        scope_file=scope_file,
        evidence_dir=evidence_dir,
        wordlists_dir=wordlists_dir,
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
        censys_api_id=os.environ.get("CENSYS_API_ID"),
        censys_api_secret=os.environ.get("CENSYS_API_SECRET"),
    )


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
