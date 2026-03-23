#!/usr/bin/env bash
# Phase 1 verification (single entry point)
# Runs docker-compose, automated tests, and manual checks in sequence.

set +e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 1

# Load .env if present
if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

MODEL="${LLM_MODEL:-gpt-4o-mini}"
RUN_REDTEAM="${RUN_REDTEAM:-1}"
REDTEAM_PROMPTS="${REDTEAM_PROMPTS:-$ROOT_DIR/tools/redteam_prompts.jsonl}"
export REDTEAM_PROMPTS

if command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  DC=(docker compose)
fi

section() {
  echo ""
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

run_curl_with_status() {
  # Usage: run_curl_with_status "Label" curl ...
  local label="$1"
  shift
  section "$label"
  "$@" -s -w "\nHTTP %{http_code}\n"
  echo ""
}

# 1) Docker-compose bring-up
section "Docker Compose: Rebuild + Start"
"${DC[@]}" down
"${DC[@]}" up -d --build
"${DC[@]}" ps

# 2) Wait for gateway health
section "Wait for /health"
HEALTH_OK=0
for i in {1..30}; do
  HEALTH_RESPONSE=$(curl -s http://localhost:8000/health)
  if [ -n "$HEALTH_RESPONSE" ]; then
    echo "$HEALTH_RESPONSE"
    HEALTH_OK=1
    break
  fi
  sleep 1
done
if [ "$HEALTH_OK" -ne 1 ]; then
  echo "Health check did not respond within timeout."
fi

# 3) Automated tests
section "Automated Tests (pytest)"
python -m pytest tests/test_gateway.py -q

# 4) Manual checks
run_curl_with_status "Get PII Policy" curl http://localhost:8000/admin/policies/pii

run_curl_with_status "PII Block Test (Expect 403)" curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"My SSN is 123-45-6789\"}]}"

run_curl_with_status "Set PII Policy to LOG_ONLY" curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"policy_name":"pii_detection","action":"LOG_ONLY"}'

run_curl_with_status "PII Test with LOG_ONLY (Should NOT block; may hit LLM)" curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"My SSN is 123-45-6789\"}]}"

run_curl_with_status "Restore PII Policy to BLOCK" curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"policy_name":"pii_detection","action":"BLOCK"}'

# 5) Cyren direct checks (may fail if outbound blocked)
section "Cyren IPRep (Direct)"
curl -qsXPOST \
  -d $'x-ctch-request-type: classifyip\nx-ctch-pver: 1.0\n\nx-ctch-ip: 8.8.8.8\n' \
  https://try-now-ipreputation.data443.io/ctipd/iprep

echo ""
section "Cyren URLF (Direct)"
curl -qsXPOST \
  -d $'x-ctch-request-type: classifyurl\r\nx-ctch-pver: 1.0\r\n\r\nx-ctch-url: https://example.com\r\n' \
  https://try-now-urlcat.data443.io/ctwsd/websec

echo ""

# 6) OpenAI proxy test (only if LLM_API_KEY is set)
if [ -n "${LLM_API_KEY:-}" ]; then
  run_curl_with_status "OpenAI Proxy Test (Safe Prompt)" curl -X POST http://localhost:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}]}"
else
  section "OpenAI Proxy Test"
  echo "Skipped (LLM_API_KEY not set in .env)"
  echo ""
fi

# 7) Red-team prompt suite (heavy prompts)
if [ "$RUN_REDTEAM" = "1" ]; then
  section "Red-Team Prompt Suite"
  python tools/redteam_runner.py
else
  section "Red-Team Prompt Suite"
  echo "Skipped (set RUN_REDTEAM=1 to enable)"
  echo ""
fi

section "Done"


