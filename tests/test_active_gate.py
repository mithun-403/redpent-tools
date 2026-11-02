"""Active authorization gate — each failing condition must block."""
import pytest

from redpent_tools.scope import ScopeError


def test_blocked_when_active_not_allowed(ctx):
    # ctx has active_allowed=False
    with pytest.raises(ScopeError) as e:
        ctx.guard.assert_active_allowed(confirm_authorized=True,
                                        engagement_id="TEST-2026-001")
    assert "active_allowed is false" in str(e.value)


def test_blocked_without_confirm(ctx_active):
    with pytest.raises(ScopeError) as e:
        ctx_active.guard.assert_active_allowed(confirm_authorized=False,
                                               engagement_id="TEST-2026-001")
    assert "confirm_authorized" in str(e.value)


def test_blocked_on_engagement_mismatch(ctx_active):
    with pytest.raises(ScopeError) as e:
        ctx_active.guard.assert_active_allowed(confirm_authorized=True,
                                               engagement_id="WRONG")
    assert "engagement_id" in str(e.value)


def test_blocked_outside_window(ctx_active):
    ctx_active.config.scope.active_window = {
        "start": "2000-01-01T00:00:00+00:00", "end": "2000-01-02T00:00:00+00:00"}
    with pytest.raises(ScopeError) as e:
        ctx_active.guard.assert_active_allowed(confirm_authorized=True,
                                               engagement_id="TEST-2026-001")
    assert "active_window" in str(e.value)


def test_blocked_when_window_missing(ctx):
    ctx.config.scope.active_allowed = True
    with pytest.raises(ScopeError) as e:
        ctx.guard.assert_active_allowed(confirm_authorized=True,
                                        engagement_id="TEST-2026-001")
    assert "active_window" in str(e.value)


def test_passes_when_all_conditions_met(ctx_active):
    # Should not raise.
    ctx_active.guard.assert_active_allowed(confirm_authorized=True,
                                           engagement_id="TEST-2026-001")


@pytest.mark.asyncio
async def test_nmap_blocked_records_audit(ctx):
    from redpent_tools.tools import active
    res = await active.nmap_scan(ctx, "example.com", confirm_authorized=True,
                                 engagement_id="TEST-2026-001")
    assert res["ok"] is False
    assert res["status"] == "blocked"
    # audit line written
    assert ctx.config.audit_log().exists()


@pytest.mark.asyncio
async def test_sqlmap_and_commix_blocked_when_gate_closed(ctx):
    from redpent_tools.tools import active
    for res in [
        await active.sqlmap_scan(ctx, "https://example.com/?id=1", confirm_authorized=True,
                                 engagement_id="TEST-2026-001"),
        await active.commix_scan(ctx, "https://example.com/?x=1", confirm_authorized=True,
                                 engagement_id="TEST-2026-001"),
    ]:
        assert res["ok"] is False and res["status"] == "blocked"


@pytest.mark.asyncio
async def test_sqlmap_level_risk_clamped(ctx_active, monkeypatch):
    """Gate open, but level/risk must clamp to scope.limits (3/2) and no dangerous flag appears."""
    from redpent_tools.tools import active
    from redpent_tools.runner import RunResult
    cap = {}

    async def fake_run(tool, cmd, **kw):
        cap["cmd"] = cmd
        return RunResult(True, 0, "", "", "", 0.1, "x.txt")

    monkeypatch.setattr(ctx_active.runner, "run", fake_run)
    res = await active.sqlmap_scan(ctx_active, "https://example.com/?id=1", level=5, risk=3,
                                   confirm_authorized=True, engagement_id="TEST-2026-001")
    assert res["level"] == 3 and res["risk"] == 2
    joined = " ".join(cap["cmd"])
    assert "--level 3" in joined and "--risk 2" in joined
    assert "--batch" in cap["cmd"]
    for danger in ("--os-shell", "--sql-shell", "--file-write", "--os-pwn"):
        assert danger not in cap["cmd"]
