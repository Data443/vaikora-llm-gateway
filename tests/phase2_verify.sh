#!/usr/bin/env bash
# Backward-compatible Phase 2 verification entrypoint.

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ ! -f "tests/sh/all.sh" ]; then
  echo "ERROR: tests/sh/all.sh not found."
  exit 1
fi

bash tests/sh/all.sh "$@"
