#!/usr/bin/env bash
# Tech Guardians VAPT Portal launcher (Linux / macOS)
# Plug-and-run: creates a local virtualenv on the stick, installs deps, launches.
set -e
cd "$(dirname "$0")"

PY=python3
command -v $PY >/dev/null 2>&1 || PY=python

if [ ! -d ".venv" ]; then
  echo "[*] First run: creating virtual environment..."
  $PY -m venv .venv
  ./.venv/bin/pip install --upgrade pip >/dev/null
  echo "[*] Installing dependencies..."
  ./.venv/bin/pip install -r requirements.txt
fi

echo "[*] Starting Tech Guardians VAPT Portal..."
exec ./.venv/bin/python app.py
