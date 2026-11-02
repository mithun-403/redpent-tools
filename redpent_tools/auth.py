"""API-key generation + a pure-ASGI auth guard for the HTTP MCP service.

When REDPENT_API_KEY is set, the HTTP service requires it on every /mcp request via
`X-API-Key: <key>` or `Authorization: Bearer <key>`. A pure-ASGI middleware is used (not
Starlette BaseHTTPMiddleware) so it never buffers the streamed SSE responses.
"""
from __future__ import annotations

import hmac
import secrets

KEY_PREFIX = "rpk_"  # redpent-tools key


def generate_key() -> str:
    """A fresh API key, e.g. rpk_<43 url-safe chars>."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def _extract(headers: list[tuple[bytes, bytes]]) -> str | None:
    h = {k.lower(): v for k, v in headers}
    if b"x-api-key" in h:
        return h[b"x-api-key"].decode("latin-1").strip()
    auth = h.get(b"authorization")
    if auth:
        s = auth.decode("latin-1").strip()
        return s[7:].strip() if s.lower().startswith("bearer ") else s
    return None


class ApiKeyMiddleware:
    """ASGI middleware: reject requests whose key doesn't match. Health path is open."""

    def __init__(self, app, api_key: str, open_paths: tuple[str, ...] = ("/health",)):
        self.app = app
        self.api_key = api_key
        self.open_paths = open_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") in self.open_paths:
            return await self.app(scope, receive, send)
        presented = _extract(scope.get("headers", []))
        if not presented or not hmac.compare_digest(presented, self.api_key):
            await _unauthorized(send)
            return
        await self.app(scope, receive, send)


async def _unauthorized(send) -> None:
    body = b'{"error":"unauthorized: missing or invalid API key (X-API-Key / Bearer)"}'
    await send({"type": "http.response.start", "status": 401,
                "headers": [(b"content-type", b"application/json"),
                            (b"www-authenticate", b"Bearer")]})
    await send({"type": "http.response.body", "body": body})
