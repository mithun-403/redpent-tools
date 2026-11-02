"""Output parsing, using saved sample outputs (no network, no binaries)."""
from pathlib import Path

import pytest

SAMPLES = Path(__file__).parent / "samples"


def test_parse_nmap_xml_open_ports_only():
    from redpent_tools.tools.active import _parse_nmap_xml
    hosts = _parse_nmap_xml(SAMPLES / "nmap-sample.xml")
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "203.0.113.5"
    open_ports = {p["port"] for p in hosts[0]["ports"]}
    assert open_ports == {22, 80}          # 81 was closed -> excluded
    svc = {p["port"]: p["service"] for p in hosts[0]["ports"]}
    assert svc[22] == "ssh" and svc[80] == "http"


@pytest.mark.asyncio
async def test_masscan_json_parse(ctx_active, monkeypatch):
    from redpent_tools.runner import RunResult
    from redpent_tools.tools import active

    json_out = ctx_active.config.evidence_path("masscan_scan") / "scan.json"
    json_out.write_text(
        '[\n{"ip":"203.0.113.5","timestamp":"1","ports":[{"port":443,"proto":"tcp"}]},\n'
        '{"ip":"203.0.113.5","timestamp":"1","ports":[{"port":80,"proto":"tcp"}]}\n]'
    )

    async def fake_run(tool_name, cmd, **kw):
        return RunResult(True, 0, "", "", "", 0.1, str(json_out))

    monkeypatch.setattr(ctx_active.runner, "run", fake_run)
    res = await active.masscan_scan(ctx_active, "203.0.113.5", ports="80,443",
                                    confirm_authorized=True, engagement_id="TEST-2026-001")
    ports = sorted(p["port"] for p in res["open_ports"])
    assert ports == [80, 443]


@pytest.mark.asyncio
async def test_ffuf_json_parse(ctx_active, monkeypatch):
    from redpent_tools.runner import RunResult
    from redpent_tools.tools import active

    wl = ctx_active.config.wordlists_dir / "common.txt"
    wl.write_text("admin\nlogin\n")
    json_out = ctx_active.config.evidence_path("ffuf_fuzz") / "ffuf.json"
    json_out.write_text(
        '{"results":[{"input":{"FUZZ":"admin"},"status":200,"length":1234,'
        '"words":10,"lines":5}]}'
    )

    async def fake_run(tool_name, cmd, **kw):
        return RunResult(True, 0, "", "", "", 0.1, str(json_out))

    async def fake_soft404(ctx, url):
        return None

    monkeypatch.setattr(ctx_active.runner, "run", fake_run)
    monkeypatch.setattr(active, "_detect_soft404", fake_soft404)
    res = await active.ffuf_fuzz(ctx_active, "https://example.com/FUZZ", "common.txt",
                                 confirm_authorized=True, engagement_id="TEST-2026-001")
    assert res["results"][0]["path"] == "admin"
    assert res["results"][0]["status"] == 200


def test_mask_secrets():
    from redpent_tools.audit import mask_secrets
    assert "AKIA" not in mask_secrets("key AKIAIOSFODNN7EXAMPLE here")
    assert "REDACTED" in mask_secrets("api_key: abcdef1234567890")
