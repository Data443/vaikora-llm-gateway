#!/usr/bin/env bash
# Entry point: run full verification, then open interactive live prompt.

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ ! -f "tests/sh/live.sh" ]; then
  echo "ERROR: tests/sh/live.sh not found."
  exit 1
fi

bash tests/sh/live.sh "$@"