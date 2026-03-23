#!/usr/bin/env bash
# Phase 2 verification (foundation checks)

set +e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

MODEL="${LLM_MODEL:-gpt-4o-mini}"

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
  local label="$1"
  shift
  section "$label"
  "$@" -s -w "\nHTTP %{http_code}\n"
  echo ""
}

section "Docker Compose: Rebuild + Start"
"${DC[@]}" down
"${DC[@]}" up -d --build
"${DC[@]}" ps

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

section "Automated Tests (pytest)"
python -m pytest -q

run_curl_with_status "Get PII Policy" curl http://localhost:8000/admin/policies/pii
run_curl_with_status "Get PII Policy Versions (latest)" curl "http://localhost:8000/admin/policies/pii_detection/versions?limit=5"

run_curl_with_status "Update PII Policy -> LOG_ONLY (versioned)" curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"action":"LOG_ONLY","changed_by":"phase2_verify","change_note":"phase2 versioning test"}'

run_curl_with_status "Get PII Policy Versions (after update)" curl "http://localhost:8000/admin/policies/pii_detection/versions?limit=5"

run_curl_with_status "Rollback PII Policy to Version 1" curl -X POST "http://localhost:8000/admin/policies/pii_detection/rollback" \
  -H "Content-Type: application/json" \
  -d '{"version":1,"changed_by":"phase2_verify"}'

run_curl_with_status "Restore PII Policy to BLOCK" curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"action":"BLOCK","changed_by":"phase2_verify","change_note":"restore baseline"}'

run_curl_with_status "Get Entitlements" curl http://localhost:8000/admin/entitlements

run_curl_with_status "Disable OpenAI Provider Entitlement" curl -X PUT http://localhost:8000/admin/entitlements \
  -H "Content-Type: application/json" \
  -d '{"providers":{"openai":false},"changed_by":"phase2_verify","change_note":"provider block test"}'

run_curl_with_status "Provider Entitlement Block Test (Expect 403)" curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}]}"

run_curl_with_status "Re-enable OpenAI Provider Entitlement" curl -X PUT http://localhost:8000/admin/entitlements \
  -H "Content-Type: application/json" \
  -d '{"providers":{"openai":true},"changed_by":"phase2_verify","change_note":"restore provider access"}'

if [ -n "${LLM_API_KEY:-}" ]; then
  run_curl_with_status "OpenAI Proxy Test (Safe Prompt)" curl -X POST http://localhost:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}]}"
else
  section "OpenAI Proxy Test"
  echo "Skipped (LLM_API_KEY not set in .env)"
  echo ""
fi

run_curl_with_status "Audit Log Query" curl "http://localhost:8000/audit/log?limit=3"
run_curl_with_status "Gateway Event Query" curl "http://localhost:8000/audit/events?limit=5"

section "Done"
