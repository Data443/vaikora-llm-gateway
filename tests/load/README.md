# Load tests (k6) — gateway vs Vaikora lanes

Prerequisites: [k6](https://k6.io/docs/get-started/installation/) installed locally or in CI.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GATEWAY_BASE_URL` | For gateway lane | e.g. `http://127.0.0.1:9000` or `https://gateway.example.com` (no trailing slash) |
| `VAIKORA_BASE_URL` | For Vaikora lane | Native Vaikora / backend base URL |
| `VAIKORA_PATH` | No | Defaults to `/health`; set to your Vaikora health or probe path |
| `PROXY_API_KEY` | If gateway enforces proxy key | Sent as `x-api-key` |
| `RUN_CHAT_LOAD` | No | Set to `true` to include `POST /v1/chat/completions` (uses upstream quota; costs may apply) |
| `LLM_MODEL` | No | Default `gpt-4o-mini` when chat load enabled |

## Commands

**Gateway lane** (health + optional chat):

```bash
export GATEWAY_BASE_URL="http://127.0.0.1:9000"
# optional: export PROXY_API_KEY="..."
# optional: export RUN_CHAT_LOAD="true"
k6 run tests/load/k6/gateway_lane.js
```

**Vaikora native lane** (GET to configurable path — adjust `VAIKORA_PATH` to match your deployment):

```bash
export VAIKORA_BASE_URL="http://vaikora-backend:8000"
export VAIKORA_PATH="/health"
k6 run tests/load/k6/vaikora_lane.js
```

## Outputs

k6 prints summary statistics to stdout. Save with:

```bash
k6 run tests/load/k6/gateway_lane.js 2>&1 | tee load-gateway-$(date -u +%Y%m%dT%H%MZ).log
```

## Relationship to client goals

- **Jason (load + Sentinel)**: default scripts stress **`/health`** (safe) and optionally chat traffic to pull policy + Cyren-adjacent paths through the gateway.
- **Native vs proxy**: run **both** scripts against the same window where possible; attach logs and Sentinel screenshots to the charter milestone.
