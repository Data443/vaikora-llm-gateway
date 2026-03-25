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
```

## 3) Full Verification (Phase 2 + Agent Governance)
```bash
bash documents/setup_and_run/phase2_verify.sh
```
Expected baseline:
- `/health` returns healthy
- tests pass
- semantic/domain/email policy checks block as expected when enabled
- managed-agent proxy returns HTTP 200
- audit/events/metrics endpoints return HTTP 200

## 4) Client Report Artifact
```bash
bash documents/setup_and_run/generate_client_report.sh
```
Outputs:
- `documents/reports/client_exec_readout_YYYYMMDD_HHMMSS.md`
- `documents/reports/artifacts_YYYYMMDD_HHMMSS/`

## 5) Production Baseline Settings
Set these in `.env` before production deployment:
- `ADMIN_AUTH_ENABLED=true`
- strong `ADMIN_API_KEY`
- strong `JWT_SECRET` if JWT is enabled
- explicit `CORS_ALLOWED_ORIGINS` (no wildcard in production)
- `TRUST_PROXY_HEADERS=true` only when running behind trusted ingress/proxy
- `AGENT_LINK_ENFORCEMENT_ENABLED=true`\r\n- `OTEL_ENABLED=true` (only when collector endpoint is configured)\r\n- `OTEL_EXPORTER_OTLP_ENDPOINT` set to your collector URL\r\n- `AUDIT_MASK_SENSITIVE_FIELDS=true`
- `AUDIT_RETENTION_DAYS` according to policy

## 6) Useful Operational Checks
```bash
# Recent events
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/events?limit=20"

# JSON metrics
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/metrics"

# Prometheus metrics
curl -H "x-admin-key: $ADMIN_API_KEY" "http://localhost:8000/audit/metrics/prometheus"
```

## 7) Troubleshooting
- `HTTP 404` on managed-agent route:
  - confirm agent exists: `GET /admin/agents/{agent_id}`
  - confirm route used: `/agents/{agent_id}/v1/chat/completions`
- `HTTP 403 entitlement_blocked`:
  - check `/admin/entitlements` provider/module flags
- Optional provider tests skipped:
  - set provider key in `.env` (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`)

