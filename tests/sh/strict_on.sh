#!/usr/bin/env bash
# Enable strict gateway security mode for live demo.

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

OPENAI_EFFECTIVE_KEY="${LLM_API_KEY:-${OPENAI_API_KEY:-}}"
OPENAI_PROVIDER=false
ANTHROPIC_PROVIDER=false
GEMINI_PROVIDER=false
OPENROUTER_PROVIDER=false

if [ -n "$OPENAI_EFFECTIVE_KEY" ]; then
  OPENAI_PROVIDER=true
fi
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  ANTHROPIC_PROVIDER=true
fi
if [ -n "${GEMINI_API_KEY:-}" ]; then
  GEMINI_PROVIDER=true
fi
if [ -n "${OPENROUTER_API_KEY:-}" ]; then
  OPENROUTER_PROVIDER=true
fi

if [[ "${STRICT_ENABLE_ALL_PROVIDERS:-false}" =~ ^[Tt][Rr][Uu][Ee]$ ]]; then
  OPENAI_PROVIDER=true
  ANTHROPIC_PROVIDER=true
  GEMINI_PROVIDER=true
  OPENROUTER_PROVIDER=true
fi

ADMIN_HEADER_ARGS=()
if [[ "${ADMIN_AUTH_ENABLED:-false}" =~ ^[Tt][Rr][Uu][Ee]$ ]]; then
  if [ -n "${ADMIN_API_KEY:-}" ]; then
    ADMIN_HEADER_ARGS=(-H "x-admin-key: ${ADMIN_API_KEY}")
  else
    echo "ERROR: ADMIN_AUTH_ENABLED=true but ADMIN_API_KEY is missing in .env"
    exit 1
  fi
fi

FAIL_COUNT=0

section() {
  echo ""
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

http_code_from_output() {
  printf "%s\n" "$1" | awk '/^HTTP [0-9]+$/ {print $2}' | tail -n1
}

run_check() {
  local label="$1"
  shift

  section "$label"
  local output
  output="$("$@" -sS -w "\nHTTP %{http_code}\n")"
  echo "$output"
  echo ""

  local code
  code="$(http_code_from_output "$output")"
  if [ "$code" != "200" ]; then
    echo "[FAIL] $label (HTTP ${code:-N/A})"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  else
    echo "[PASS] $label"
  fi
}

section "Health Check"
HEALTH_OUTPUT="$(curl -sS -w "\nHTTP %{http_code}\n" http://localhost:8000/health)"
echo "$HEALTH_OUTPUT"
echo ""
HEALTH_CODE="$(http_code_from_output "$HEALTH_OUTPUT")"
if [ "$HEALTH_CODE" != "200" ]; then
  echo "Gateway is not healthy (HTTP ${HEALTH_CODE:-N/A}). Start gateway first."
  exit 1
fi

section "Provider Entitlements Plan"
echo "openai: ${OPENAI_PROVIDER}"
echo "anthropic: ${ANTHROPIC_PROVIDER}"
echo "gemini: ${GEMINI_PROVIDER}"
echo "openrouter: ${OPENROUTER_PROVIDER}"
echo "STRICT_ENABLE_ALL_PROVIDERS: ${STRICT_ENABLE_ALL_PROVIDERS:-false}"

run_check "Enable Strict Entitlements" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/entitlements -H "Content-Type: application/json" -d '{
  "modules": {
    "pii_detection": true,
    "jailbreak_detection": true,
    "injection_detection": true,
    "semantic_detection": true,
    "domain_risk_scoring": true,
    "email_classification": true
  },
  "providers": {
    "openai": '"${OPENAI_PROVIDER}"',
    "anthropic": '"${ANTHROPIC_PROVIDER}"',
    "gemini": '"${GEMINI_PROVIDER}"',
    "openrouter": '"${OPENROUTER_PROVIDER}"'
  },
  "changed_by": "strict_on_script",
  "change_note": "enable strict protections for live demo"
}'

run_check "Set PII Policy = BLOCK/LOW" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/pii -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "severity_threshold": "LOW",
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

run_check "Set Jailbreak Policy = BLOCK" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/jailbreak -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "max_attempts": 3,
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

run_check "Set Injection Policy = BLOCK" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/injection -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

run_check "Set Semantic Policy = BLOCK/LOW" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/semantic -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "severity_threshold": "LOW",
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

run_check "Set Domain Risk Policy = BLOCK/LOW" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/domain-risk -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "severity_threshold": "LOW",
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

run_check "Set Email Classification Policy = BLOCK/LOW" curl "${ADMIN_HEADER_ARGS[@]}" -X PUT http://localhost:8000/admin/policies/email-classification -H "Content-Type: application/json" -d '{
  "enabled": true,
  "action": "BLOCK",
  "severity_threshold": "LOW",
  "changed_by": "strict_on_script",
  "change_note": "strict mode"
}'

section "Current Effective Settings"
run_check "Get Entitlements" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/entitlements
run_check "Get PII Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/pii
run_check "Get Jailbreak Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/jailbreak
run_check "Get Injection Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/injection
run_check "Get Semantic Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/semantic
run_check "Get Domain Risk Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/domain-risk
run_check "Get Email Classification Policy" curl "${ADMIN_HEADER_ARGS[@]}" http://localhost:8000/admin/policies/email-classification

section "Summary"
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "Strict mode enabled successfully."
  exit 0
fi

echo "Completed with ${FAIL_COUNT} failure(s)."
exit 1
