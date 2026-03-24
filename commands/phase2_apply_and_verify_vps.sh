#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Clean stale bytecode caches; they can trigger pytest import mismatch errors.
find . -type d -name __pycache__ -prune -exec rm -rf {} +
find . -type f -name '*.pyc' -delete

unset PYTEST_ADDOPTS || true
PYTEST_ARGS=(-q --import-mode=importlib tests -o asyncio_default_fixture_loop_scope=function)
if [[ -d "${REPO_ROOT}/data443-llm-gateway/tests" ]]; then
  echo "WARNING: nested repo copy detected at ${REPO_ROOT}/data443-llm-gateway"
  echo "Pytest will ignore that nested path for this run."
  PYTEST_ARGS+=(--ignore="${REPO_ROOT}/data443-llm-gateway")
fi

python -m pytest "${PYTEST_ARGS[@]}" | tee phase2_pytest_output.txt
bash documents/setup_and_run/phase2_verify.sh | tee phase2_verify_output.txt
docker compose logs gateway --tail=250 | tee phase2_gateway_tail.log