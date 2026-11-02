#!/usr/bin/env bash
# Run redpent-tools as a persistent HTTP MCP service (the "separate entity" RedPentAI
# integrates with). Reads scope.yaml from this repo by default.
#
#   ./run.sh                 # serve on 127.0.0.1:8971  (REDPENT_HTTP_PORT to override)
#   REDPENT_HTTP_PORT=9000 ./run.sh
set -uo pipefail
cd "$(dirname "$0")"

PORT="${REDPENT_HTTP_PORT:-8971}"
HOST="${REDPENT_HTTP_HOST:-127.0.0.1}"
export REDPENT_SCOPE_FILE="${REDPENT_SCOPE_FILE:-$PWD/scope.yaml}"
export REDPENT_EVIDENCE_DIR="${REDPENT_EVIDENCE_DIR:-$PWD/evidence}"
export REDPENT_WORDLISTS_DIR="${REDPENT_WORDLISTS_DIR:-$PWD/wordlists}"

BIN="$PWD/.venv/bin/redpent-tools"
[ -x "$BIN" ] || BIN="redpent-tools"   # fall back to a global install

echo "redpent-tools HTTP MCP service -> http://$HOST:$PORT/mcp  (scope: $REDPENT_SCOPE_FILE)"
exec "$BIN" --http --host "$HOST" --port "$PORT"
