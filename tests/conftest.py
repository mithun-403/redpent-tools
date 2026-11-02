"""Shared test fixtures. No network is used in any test."""
import pytest

from redpent_tools.audit import Auditor
from redpent_tools.config import Config, Limits, Scope
from redpent_tools.context import ReconContext
from redpent_tools.runner import Runner
from redpent_tools.scope import ScopeGuard


def make_scope(**over):
    base = dict(
        engagement_id="TEST-2026-001",
        roe_reference="unit-test",
        tester="tester@example.com",
        in_scope_domains=["example.com", "*.example.com"],
        in_scope_cidrs=["203.0.113.0/24"],
        out_of_scope=["admin.example.com", "203.0.113.10/32"],
        active_allowed=False,
        active_window={},
        limits=Limits(masscan_max_rate=1000, ffuf_max_threads=10, nmap_max_timing=4),
    )
    base.update(over)
    return Scope(**base)


@pytest.fixture
def ctx(tmp_path):
    scope = make_scope()
    cfg = Config(
        scope=scope,
        scope_file=tmp_path / "scope.yaml",
        evidence_dir=tmp_path / "evidence",
        wordlists_dir=tmp_path / "wordlists",
    )
    cfg.wordlists_dir.mkdir(parents=True, exist_ok=True)
    return ReconContext(config=cfg, guard=ScopeGuard(cfg),
                        auditor=Auditor(cfg), runner=Runner(cfg))


@pytest.fixture
def ctx_active(tmp_path):
    """Context with the active gate fully open (wide window, active_allowed)."""
    scope = make_scope(
        active_allowed=True,
        active_window={"start": "2000-01-01T00:00:00+00:00",
                       "end": "2100-01-01T00:00:00+00:00"},
    )
    cfg = Config(
        scope=scope,
        scope_file=tmp_path / "scope.yaml",
        evidence_dir=tmp_path / "evidence",
        wordlists_dir=tmp_path / "wordlists",
    )
    cfg.wordlists_dir.mkdir(parents=True, exist_ok=True)
    return ReconContext(config=cfg, guard=ScopeGuard(cfg),
                        auditor=Auditor(cfg), runner=Runner(cfg))
