#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/data443-llm-gateway

# Avoid inherited import/test options from shell/session config.
unset PYTHONPATH || true
unset PYTEST_ADDOPTS || true

# Move any accidental nested repo copies out of this repo root.
mkdir -p /workspaces/.repo-backups
while IFS= read -r -d '' d; do
  base="$(basename "$d")"
  target="/workspaces/.repo-backups/$base"
  if [ -e "$target" ]; then
    i=1
    while [ -e "${target}.dup${i}" ]; do
      i=$((i+1))
    done
    target="${target}.dup${i}"
  fi
  mv "$d" "$target"
  echo "Moved nested copy: $d -> $target"
done < <(find . -mindepth 1 -maxdepth 1 -type d -name 'data443-llm-gateway*' -print0)

# Clear stale Python caches.
find . -type d -name __pycache__ -prune -exec rm -rf {} +
find . -type f -name '*.pyc' -delete

# Run only the canonical root tests path.
python -m pytest -q --import-mode=importlib tests | tee phase2_pytest_output.txt
bash documents/setup_and_run/phase2_verify.sh | tee phase2_verify_output.txt
docker compose logs gateway --tail=250 | tee phase2_gateway_tail.log