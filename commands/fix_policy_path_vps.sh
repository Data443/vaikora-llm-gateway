#!/usr/bin/env bash
set +e

cd /workspaces/data443-llm-gateway || exit 1

echo "=== STEP 1: Current folders ==="
ls -la

echo "=== STEP 2: Check misplaced root policy folder ==="
if [ -d policy ]; then
  echo "FOUND root policy folder"
  ls -la policy
else
  echo "No root policy folder found"
fi

echo "=== STEP 3: Ensure gateway/policy exists ==="
mkdir -p gateway/policy

echo "=== STEP 4: Move policy python files into gateway/policy ==="
if [ -d policy ]; then
  mv policy/*.py gateway/policy/ 2>/dev/null || true
fi

echo "=== STEP 5: Fix __init__.py name if needed ==="
if [ -f gateway/policy/_init__.py ] && [ ! -f gateway/policy/__init__.py ]; then
  mv gateway/policy/_init__.py gateway/policy/__init__.py
fi

echo "=== STEP 6: Final folder state ==="
ls -la gateway/policy

echo "=== STEP 7: Runtime import check ==="
python -c "import gateway.policy.store as s; print('IMPORT_OK', s.__file__)"

echo "=== STEP 8: Phase 2 store tests ==="
python -m pytest -q tests/test_phase2_policy_store.py

echo "=== DONE ==="
echo "If VS Code still shows red import errors, run: Python: Restart Language Server"
