#!/usr/bin/env bash
# Thin wrapper for install.py. Picks the best Python on PATH.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PY="$candidate"; break
    fi
  done
fi
if [ -z "$PY" ]; then
  echo "No Python interpreter found on PATH. Install Python 3.10+ and try again." >&2
  exit 1
fi
exec "$PY" install.py "$@"
