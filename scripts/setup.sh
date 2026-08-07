#!/usr/bin/env bash
# CloudGuard - local development setup.
# Creates a virtualenv, installs dependencies, and initializes the database.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> CloudGuard setup"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.11+ and re-run." >&2
  exit 1
fi

PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "==> Using Python $PY_VERSION"

if [ ! -d ".venv" ]; then
  echo "==> Creating virtual environment (.venv)"
  "$PYTHON_BIN" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Installing dependencies"
pip install --upgrade pip -q
pip install -q -r backend/requirements-dev.txt

if [ ! -f "backend/.env" ]; then
  echo "==> Creating backend/.env from .env.example"
  cp .env.example backend/.env
fi

echo "==> Running test suite"
(cd backend && python -m pytest -q)

echo ""
echo "==> Setup complete."
echo ""
echo "Next steps:"
echo "  source .venv/bin/activate"
echo "  ./scripts/run.sh          # start the API + dashboard on http://localhost:8000"
echo ""
