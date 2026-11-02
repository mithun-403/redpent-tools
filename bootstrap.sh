#!/usr/bin/env bash
# One-shot setup: create a venv, install the Python package, and (via the post-install
# hook) install the CLI recon tools for this OS. After this, the whole app + its tools
# are ready.
#
#   ./bootstrap.sh            # full install (package + all tools)
#   ./bootstrap.sh --passive  # package + passive/boundary tools only
set -uo pipefail
cd "$(dirname "$0")"

LANE="${1:-all}"
PY="${PYTHON:-python3}"

echo "==> Creating virtual environment (.venv)"
"$PY" -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Installing the redpent-tools Python package"
pip install --upgrade pip >/dev/null
pip install -e ".[dev]"

# Modern `pip install -e .` uses the PEP 517 build backend and does NOT run setup.py's
# post-install command, so we install the CLI tools explicitly here. (The setup.py hook
# remains as a best-effort bonus for legacy `python setup.py install`.)
echo "==> Installing the CLI recon tools for this OS (lane=$LANE)"
redpent-tools-install "$LANE" || echo "   (some tools may have failed; see output above)"

echo "==> Verifying tool availability"
redpent-tools-install --check || true

echo
echo "==> Done. Next:"
echo "    cp scope.example.yaml scope.yaml && \$EDITOR scope.yaml"
echo "    source .venv/bin/activate && python -m redpent_tools.server"
