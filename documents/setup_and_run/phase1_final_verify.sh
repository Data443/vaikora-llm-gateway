#!/usr/bin/env bash
# Final Phase 1 verification wrapper.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

bash tests/phase1_verify.sh | tee p1_final.txt
curl -s -o /tmp/audit.json -w "AUDIT HTTP %{http_code}\n" "http://localhost:8000/audit/log?limit=3"
cat /tmp/audit.json

