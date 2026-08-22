#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

if [ ! -d .venv ]; then
  echo "Creating a virtual environment..."
  "$PY" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

if ! python -c "import flask, httpx, truststore" >/dev/null 2>&1; then
  echo "Installing dependencies..."
  python -m pip install --upgrade pip >/dev/null
  python -m pip install -r requirements.txt
fi

exec python -m blanktrail_demo "$@"
