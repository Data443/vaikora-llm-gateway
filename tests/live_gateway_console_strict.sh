#!/usr/bin/env bash
# Entry point: strict mode + interactive live prompt.

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ ! -f "tests/sh/live_strict.sh" ]; then
  echo "ERROR: tests/sh/live_strict.sh not found."
  exit 1
fi

bash tests/sh/live_strict.sh "$@"
