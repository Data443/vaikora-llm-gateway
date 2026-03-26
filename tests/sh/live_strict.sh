#!/usr/bin/env bash
# Run full verification, enable strict mode, then open interactive live prompt.

set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ -f "$ROOT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

MODEL="${LLM_MODEL:-gpt-4o-mini}"
OPENAI_EFFECTIVE_KEY="${LLM_API_KEY:-${OPENAI_API_KEY:-}}"
LIVE_SHOW_RAW="${LIVE_SHOW_RAW:-true}"
RUN_FULL_VERIFY="${RUN_FULL_VERIFY:-true}"

section() {
  echo ""
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

if [[ "$RUN_FULL_VERIFY" =~ ^[Tt][Rr][Uu][Ee]$ ]]; then
  section "Run Full Verification"
  bash tests/sh/all.sh
  VERIFY_EXIT=$?

  echo ""
  echo "Verification exit code: $VERIFY_EXIT"

  if [ "$VERIFY_EXIT" -ne 0 ] && [[ "${ALLOW_LIVE_ON_FAIL:-false}" != "true" ]]; then
    echo "Verification failed. Not starting live prompt."
    echo "Set ALLOW_LIVE_ON_FAIL=true to override."
    exit "$VERIFY_EXIT"
  fi
else
  section "Run Full Verification"
  echo "Skipped (RUN_FULL_VERIFY=${RUN_FULL_VERIFY})"
fi

section "Enable Strict Mode"
bash tests/sh/strict_on.sh
STRICT_EXIT=$?
if [ "$STRICT_EXIT" -ne 0 ]; then
  echo "Strict mode setup failed (exit $STRICT_EXIT)."
  exit "$STRICT_EXIT"
fi

section "Interactive Live Prompt (Strict Mode ON)"
HEALTH_OUTPUT="$(curl -s -w "\nHTTP %{http_code}\n" http://localhost:8000/health)"
HEALTH_CODE="$(printf "%s\n" "$HEALTH_OUTPUT" | awk '/^HTTP [0-9]+$/ {print $2}' | tail -n1)"
if [ "$HEALTH_CODE" != "200" ]; then
  echo "$HEALTH_OUTPUT"
  echo "Gateway health is not OK (HTTP ${HEALTH_CODE:-N/A})."
  echo "Fix gateway first, then rerun this script."
  exit 1
fi

echo "Gateway is healthy."
echo "Model: $MODEL"
if [ -n "$OPENAI_EFFECTIVE_KEY" ]; then
  echo "Auth: using key from .env"
else
  echo "Auth: no LLM_API_KEY/OPENAI_API_KEY in .env (requests may fail)"
fi

echo ""
echo "Type messages and press Enter."
echo "Type 'exit' to quit."

while true; do
  printf "\nYou> "
  IFS= read -r USER_INPUT || break

  if [ -z "$USER_INPUT" ]; then
    continue
  fi

  case "${USER_INPUT,,}" in
    exit|quit|q)
      echo "Exiting interactive prompt."
      break
      ;;
  esac

  PAYLOAD="$(python - "$MODEL" "$USER_INPUT" <<'PY'
import json
import sys

model = sys.argv[1]
prompt = sys.argv[2]
print(json.dumps({
    "model": model,
    "messages": [{"role": "user", "content": prompt}]
}))
PY
)"

  if [ -n "$OPENAI_EFFECTIVE_KEY" ]; then
    RESPONSE_WITH_CODE="$(curl -sS -X POST http://localhost:8000/v1/chat/completions \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${OPENAI_EFFECTIVE_KEY}" \
      -d "$PAYLOAD" \
      -w "\nHTTP %{http_code}\n")"
  else
    RESPONSE_WITH_CODE="$(curl -sS -X POST http://localhost:8000/v1/chat/completions \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" \
      -w "\nHTTP %{http_code}\n")"
  fi

  HTTP_CODE="$(printf "%s\n" "$RESPONSE_WITH_CODE" | awk '/^HTTP [0-9]+$/ {print $2}' | tail -n1)"
  RAW_BODY="$(printf "%s\n" "$RESPONSE_WITH_CODE" | sed '/^HTTP [0-9][0-9][0-9]$/d')"

  if [[ "$LIVE_SHOW_RAW" == "true" ]]; then
    echo ""
    echo "[RAW HTTP $HTTP_CODE]"
    echo "$RAW_BODY"
  fi

  RAW_RESPONSE="$RAW_BODY" python - <<'PY'
import json
import os

raw = os.environ.get("RAW_RESPONSE", "").strip()
if not raw:
    print("Gateway> (empty response)")
    raise SystemExit(0)

try:
    payload = json.loads(raw)
except Exception:
    print("Gateway> (non-JSON response)")
    print(raw)
    raise SystemExit(0)

err = payload.get("error") if isinstance(payload, dict) else None
if isinstance(err, dict):
    print("Gateway Error>", err.get("message", "Unknown error"))
    code = err.get("code")
    if code is not None:
        print("Code:", code)
    raise SystemExit(0)

choices = payload.get("choices") if isinstance(payload, dict) else None
if isinstance(choices, list) and choices:
    first = choices[0] if isinstance(choices[0], dict) else {}
    msg = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = msg.get("content")

    if isinstance(content, str) and content.strip():
        print("Gateway>", content.strip())
    elif isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            print("Gateway>", "".join(parts).strip())
        else:
            print("Gateway> (response received without text content)")
    else:
        print("Gateway> (response received without text content)")
else:
    print("Gateway> (unexpected response shape)")
    print(json.dumps(payload, indent=2))
PY

done
