"""API-key generation + ASGI auth-guard behavior (no network)."""
import pytest

from redpent_tools.auth import ApiKeyMiddleware, generate_key


def test_generate_key_shape():
    k = generate_key()
    assert k.startswith("rpk_") and len(k) > 20
    assert generate_key() != generate_key()  # random


class _Recorder:
    def __init__(self):
        self.events = []

    async def send(self, ev):
        self.events.append(ev)

    def status(self):
        for e in self.events:
            if e["type"] == "http.response.start":
                return e["status"]
        return None


async def _noop_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _scope(path="/mcp", headers=None):
    return {"type": "http", "path": path, "headers": headers or []}


async def _recv():
    return {"type": "http.request"}


@pytest.mark.asyncio
async def test_missing_key_rejected():
    mw = ApiKeyMiddleware(_noop_app, "rpk_secret")
    rec = _Recorder()
    await mw(_scope(), _recv, rec.send)
    assert rec.status() == 401


@pytest.mark.asyncio
async def test_wrong_key_rejected():
    mw = ApiKeyMiddleware(_noop_app, "rpk_secret")
    rec = _Recorder()
    await mw(_scope(headers=[(b"x-api-key", b"rpk_nope")]), _recv, rec.send)
    assert rec.status() == 401


@pytest.mark.asyncio
async def test_correct_key_passes_via_xapikey_and_bearer():
    mw = ApiKeyMiddleware(_noop_app, "rpk_secret")
    for hdrs in ([(b"x-api-key", b"rpk_secret")],
                 [(b"authorization", b"Bearer rpk_secret")]):
        rec = _Recorder()
        await mw(_scope(headers=hdrs), _recv, rec.send)
        assert rec.status() == 200


@pytest.mark.asyncio
async def test_health_path_is_open():
    mw = ApiKeyMiddleware(_noop_app, "rpk_secret")
    rec = _Recorder()
    await mw(_scope(path="/health"), _recv, rec.send)
    assert rec.status() == 200
