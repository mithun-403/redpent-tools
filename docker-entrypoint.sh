#!/usr/bin/env bash
# redpent-tools container entrypoint.
#   - Ensures an API key exists (generates one on first start if not supplied), persisting
#     it to a volume so it is stable across restarts, and prints it to the logs.
#   - Starts the HTTP MCP service with API-key auth enabled.
# Override the key by passing -e REDPENT_API_KEY=... ; override the persist path with
# REDPENT_API_KEY_FILE.
set -euo pipefail

KEY_FILE="${REDPENT_API_KEY_FILE:-/data/redpent-api-key}"

if [ -z "${REDPENT_API_KEY:-}" ]; then
  if [ -f "$KEY_FILE" ]; then
    REDPENT_API_KEY="$(cat "$KEY_FILE")"
    SRC="loaded from $KEY_FILE"
  else
    REDPENT_API_KEY="$(redpent-tools-keygen)"
    mkdir -p "$(dirname "$KEY_FILE")"
    printf '%s' "$REDPENT_API_KEY" > "$KEY_FILE"
    chmod 600 "$KEY_FILE" || true
    SRC="generated (persisted to $KEY_FILE)"
  fi
else
  SRC="from REDPENT_API_KEY env"
fi
export REDPENT_API_KEY

echo "============================================================"
echo "  redpent-tools HTTP MCP service"
echo "  API key ($SRC):"
echo "      $REDPENT_API_KEY"
echo "  In RedPentAI: transport=http, url=http://<host>:${REDPENT_HTTP_PORT:-8971}/mcp,"
echo "                env/header  X-API-Key=$REDPENT_API_KEY"
echo "============================================================"

exec redpent-tools --http --host "${REDPENT_HTTP_HOST:-0.0.0.0}" --port "${REDPENT_HTTP_PORT:-8971}"
