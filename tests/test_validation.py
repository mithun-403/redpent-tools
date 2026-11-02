"""Strict input validation + rate/thread/timing clamping."""
import pytest

from redpent_tools.tools import utils
from redpent_tools.tools.utils import ValidationError


def test_valid_domain():
    assert utils.valid_domain("Example.COM.") == "example.com"
    assert utils.valid_domain("a.b.example.com") == "a.b.example.com"


@pytest.mark.parametrize("bad", ["notadomain", "ex ample.com", "-bad.com", "a..b.com", "x`.com"])
def test_invalid_domain(bad):
    with pytest.raises(ValidationError):
        utils.valid_domain(bad)


def test_valid_ip_and_cidr():
    assert utils.valid_ip("203.0.113.5") == "203.0.113.5"
    assert utils.valid_cidr("203.0.113.0/24") == "203.0.113.0/24"


def test_invalid_ip():
    with pytest.raises(ValidationError):
        utils.valid_ip("999.1.1.1")


def test_valid_ports():
    assert utils.valid_ports("top-1000") == "top-1000"
    assert utils.valid_ports("80,443") == "80,443"
    assert utils.valid_ports("1-65535") == "1-65535"


@pytest.mark.parametrize("bad", ["80;rm", "99999", "abc", "80,70000"])
def test_invalid_ports(bad):
    with pytest.raises(ValidationError):
        utils.valid_ports(bad)


def test_url_rejects_injection():
    with pytest.raises(ValidationError):
        utils.valid_url("http://example.com/`whoami`")
    with pytest.raises(ValidationError):
        utils.valid_url("ftp://example.com")
    assert utils.valid_url("https://example.com/a") == "https://example.com/a"


def test_wordlist_must_be_inside_allowed_dir(tmp_path):
    allowed = tmp_path / "wordlists"
    allowed.mkdir()
    wl = allowed / "common.txt"
    wl.write_text("admin\nlogin\n")
    assert utils.valid_wordlist("common.txt", allowed) == wl.resolve()
    # path traversal must be rejected
    with pytest.raises(ValidationError):
        utils.valid_wordlist("../../etc/passwd", allowed)


def test_clamp():
    assert utils.clamp(5000, 1, 1000) == 1000
    assert utils.clamp(0, 1, 1000) == 1
    assert utils.clamp(50, 1, 1000) == 50


@pytest.mark.asyncio
async def test_masscan_rate_is_clamped(ctx_active, monkeypatch):
    """Even with an open gate, rate must be clamped to scope.limits.masscan_max_rate."""
    from redpent_tools.tools import active
    captured = {}

    async def fake_run(tool_name, cmd, **kw):
        captured["cmd"] = cmd
        from redpent_tools.runner import RunResult
        return RunResult(True, 0, "", "", "", 0.1, "x.txt")

    monkeypatch.setattr(ctx_active.runner, "run", fake_run)
    # ask for rate 999999 -> must be clamped to 1000
    res = await active.masscan_scan(ctx_active, "203.0.113.5", ports="80",
                                    rate=999999, confirm_authorized=True,
                                    engagement_id="TEST-2026-001")
    assert res["rate_used"] == 1000
    assert "1000" in captured["cmd"]
