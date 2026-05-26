#!/usr/bin/env bash
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
  echo "No Python interpreter found on PATH." >&2
  exit 1
fi
exec "$PY" update.py "$@"
