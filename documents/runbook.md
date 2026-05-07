# Gateway Runbook

Last updated: 2026-03-25

## 1) Prerequisites
- Docker + Docker Compose installed
- `.env` present (copy from `.env.example`)
- At minimum for OpenAI verification: `LLM_API_KEY` or `OPENAI_API_KEY`

## 2) Start/Restart
```bash
docker compose down
docker compose up -d --build
docker compose ps
curl http://localhost:8000/health
curl -i http://localhost:8000/ready
```

Production-style (safer host exposure):
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```
Notes:
- `/health` is liveness/diagnostics.
- `/ready` is strict readiness and returns `503` when dependencies are degraded.

## 3) Full Verification (Phase 2 + Agent Governance)
```bash
bash tests/phase2_verify.sh
```
Expected baseline:
- `/health` returns healthy
- tests pass
- semantic/domain/email policy checks block as expected when enabled
- managed-agent proxy returns HTTP 200
- audit/events/metrics endpoints return HTTP 200

## 4) Live Console Runner
```bash
bash tests/live_gateway_console.sh
```
Outputs:
- runs full `tests/phase2_verify.sh` and prints all outputs to terminal
- then opens an interactive prompt for live requests to the gateway

## 5) Production Baseline Settings
Set these in `.env` before production deployment:
- `ADMIN_AUTH_ENABLED=true`
- `ADMIN_AUTH_MODE=api_key|jwt|api_key_or_jwt`
- strong `ADMIN_API_KEY` and optional `ADMIN_ALLOWED_IPS`
- strong `JWT_SECRET` if JWT is enabled
- `STRICT_STARTUP_VALIDATION=true` (fail fast on insecure startup config)
- `RATE_LIMIT_ENABLED=true` + `RATE_LIMIT_STORAGE=auto|redis` with tuned limits
- explicit `CORS_ALLOWED_ORIGINS` (no wildcard in production)
- `TRUST_PROXY_HEADERS=true` only when running behind trusted ingress/proxy
- `AGENT_LINK_ENFORCEMENT_ENABLED=true`
- `OTEL_ENABLED=true` (only when collector endpoint is configured)
- `OTEL_EXPORTER_OTLP_ENDPOINT` set to your collector URL
- `AUDIT_MASK_SENSITIVE_FIELDS=true`
- `AUDIT_RETENTION_DAYS` according to policy
- `AUDIT_PURGE_ENABLED=true` and tune `AUDIT_PURGE_INTERVAL_SECONDS`
- `DB_MIGRATIONS_ENABLED=true` (`DB_DDL_BOOTSTRAP_FALLBACK=false`)
- if using control plane:
  - `CONTROL_PLANE_ENABLED=true`
  - set valid `CONTROL_PLANE_URL` and `CONTROL_PLANE_API_KEY`
  - tune sync/poll/timeout intervals

## 6) Useful Operational Checks
```bash
# Recent events
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/events?limit=20"

# JSON metrics
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/metrics"

# Prometheus metrics
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/metrics/prometheus"

# Readiness (should be HTTP 200 in steady state)
curl -i http://localhost:8000/ready
```

## 7) Kubernetes Deployment Checklist
- Liveness probe path: `/health`
- Readiness probe path: `/ready`
- Set non-placeholder secrets for:
  - `PROXY_API_KEY`
  - `ADMIN_API_KEY` (if admin auth enabled)
  - `JWT_SECRET` (if JWT enabled)
  - `CONTROL_PLANE_API_KEY` (if control plane enabled)
- Confirm rollout only after readiness is green:
  - `kubectl get pods`
  - `kubectl describe pod <pod>`
  - `kubectl logs <pod>`
- Validate live endpoints from inside cluster or ingress:
  - `GET /health` -> 200
  - `GET /ready` -> 200

## 8) CI/CD Release Gates
- CI workflow (`.github/workflows/ci.yml`) must pass:
  - dependency checks + vulnerability scan
  - unit/integration tests
  - Docker image build
  - Helm lint/template checks
- Release workflow (`.github/workflows/release.yml`) must pass:
  - fast security regression suite
  - Docker image build + Trivy scan
  - optional GHCR push + Cosign signing on tagged/manual release

## 9) Troubleshooting
- `HTTP 404` on managed-agent route:
  - confirm agent exists: `GET /admin/agents/{agent_id}`
  - confirm route used: `/agents/{agent_id}/v1/chat/completions`
- `HTTP 403 entitlement_blocked`:
  - check `/admin/entitlements` provider/module flags
- `HTTP 503` on `/ready`:
  - check `/health` component details
  - inspect Redis/Postgres/control-plane connectivity
- Optional provider tests skipped:
  - set provider key in `.env` (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`)




