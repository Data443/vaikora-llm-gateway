# Data443 LLM Security Gateway

Production-ready LLM reverse-proxy security gateway. The gateway intercepts every request and response, evaluates deterministic security policies, and enforces ALLOW/BLOCK/CONSTRAIN decisions before traffic reaches the LLM.

---

**Status**
- Phase 1: Production-ready prototype complete
- Phase 2 implementation scope in this repo: verified (policy lifecycle, entitlements, content controls, telemetry, managed-agent governance)
- Test suite: 87 tests passing
- End-to-end verification: OpenAI + Cyren IPRep/URLF confirmed, including managed-agent proxy path

---

**Key Capabilities**
- Reverse-proxy traffic interception and normalization
- Optional JWT authentication on inbound requests
- PII detection (SSN, email, phone, credit card, IP, passport, bank account)
- Malicious prompt detection (jailbreak and injection patterns)
- Semantic abuse detection module (entitlement-gated)
- Domain risk scoring module (entitlement-gated)
- Email classification risk module (entitlement-gated)
- Data443 Cyren IP reputation and URL classification
- Deterministic policy engine (no LLM in the decision path)
- L1 in-memory + L2 Redis caching for Cyren lookups
- Immutable audit log in PostgreSQL
- Circuit breaker for external dependency failures
- Admin API for hot policy updates
- Sensitive policy fields are redacted in admin API responses
- Policy versioning with rollback support
- Entitlement-aware provider/model enforcement
- Entitlement-aware input/output size limits
- Multi-provider adapter layer (OpenAI, Anthropic, Gemini, OpenRouter)
- Structured gateway event stream (`/audit/events`)
- Telemetry metrics endpoint (`/audit/metrics`)
- Prometheus metrics endpoint (`/audit/metrics/prometheus`)
- Optional OpenTelemetry trace hooks (policy + upstream spans)
- Managed agent registry (`create/wrap/list/get`)
- A2A link + interaction governance APIs (create/approve/block/get)
- Approved-link enforcement before A2A interaction creation
- Agent metadata policy constraints for source->target interaction rules
- Agent interaction retention + time-window filtering
- Managed-agent proxy route (`/agents/{agent_id}/v1/chat/completions`)
- JSON response inspection for policy enforcement
- Detector/cache/error telemetry counters + agent governance Prometheus counters

---

**Architecture (High Level)**

Current build (text diagram):

```text
                           +-----------------------------------+
                           |         Control (Vaikora)         |
                           |-----------------------------------|
                           | Agent Mgmt                        |
                           | Interaction Mgmt                  |
                           | Policy / Entitlement Mgmt         |
                           | Audit / Metrics Access            |
                           +----------------+------------------+
                                            |
                create/wrap/list/get        | approve/block/review
                                            v
+-----------------------------------+   +-----------------------------------+
|               Agents              |   |      Enforcement (Gateway)        |
|-----------------------------------|   |-----------------------------------|
| agent-1  <---- A2A ---->  agent-2 |-->| Ingress:                          |
| agent-2  <---- A2A ---->  agent-3 |   | - /v1/chat/completions            |
+-----------------------------------+   | - /agents/{agent_id}/v1/chat/...  |
                                        |                                    |
                                        | Request pipeline:                  |
                                        | 1) Optional JWT auth               |
                                        | 2) Entitlement checks              |
                                        | 3) Content filter                  |
                                        |    - PII                           |
                                        |    - jailbreak / injection         |
                                        |    - semantic / domain / email     |
                                        | 4) Cyren policy scoring            |
                                        | 5) Decision: ALLOW/BLOCK/CONSTRAIN |
                                        | 6) Provider adapter + proxy        |
                                        | 7) Response inspection             |
                                        | 8) Audit + telemetry emit          |
                                        +----------------+-------------------+
                                                         |
                                                         v
                                 +-----------------------------------------+
                                 |            Provider Router              |
                                 |-----------------------------------------|
                                 | OpenAI | Anthropic | Gemini | OpenRouter|
                                 +-----------------------------------------+
```

Flow summary:
1. Client or managed agent sends request to gateway ingress.
2. Gateway enforces auth, entitlements, and deterministic policy controls.
3. Allowed traffic is normalized and routed to the selected upstream provider.
4. Response is normalized back to OpenAI-compatible shape.
5. Audit/events/metrics are written for governance and observability.

---

**Decision Logic**

| Cyren Score | Trust Level | Action |
|-------------|-------------|--------|
| 80-100 | HIGH | ALLOW |
| 50-79 | MEDIUM | ALLOW with logging |
| 20-49 | LOW | CONSTRAIN |
| 0-19 | CRITICAL | BLOCK |

---

**Quick Start (Docker)**

```bash
git clone https://github.com/joseph88gomez/data443-llm-gateway.git
cd data443-llm-gateway
cp .env.example .env
docker-compose up -d --build
curl http://localhost:8000/health
```

Note: Set `LLM_ENDPOINT` to `https://api.openai.com` (no `/v1`). For testing, set `LLM_API_KEY`. For pass-through keys, leave `LLM_API_KEY` empty and send `Authorization: Bearer <key>` from the client.

---

**Health Check Response**

```json
{
  "status": "healthy",
  "circuit_breaker": "closed",
  "cache_connected": true,
  "audit_connected": true
}
```

---

**Phase 1 Verification (Single Script)**

```bash
bash tests/phase1_verify.sh
```

This runs:
- Docker rebuild + startup
- Health check
- Pytest suite
- PII policy tests (BLOCK + LOG_ONLY)
- OpenAI proxy check
- Red-team prompt suite

Red-team results are saved to:
`tools/redteam_results_YYYYMMDD_HHMMSS.jsonl`

---

**Phase 2 Foundation Verification**

```bash
bash documents/setup_and_run/phase2_verify.sh
```

This verifies:
- policy versioning and rollback endpoints
- entitlement update and provider gating behavior
- semantic detector entitlement/policy enforcement path
- domain risk policy/entitlement enforcement path
- email classification policy/entitlement enforcement path
- managed agent create/wrap + A2A link/interaction workflow
- optional Anthropic/Gemini/OpenRouter checks (if keys are configured)
- structured gateway event query endpoint
- telemetry metrics endpoint + Prometheus metrics endpoint
- interaction approve/block workflow (`/admin/interactions/{request_id}`)
- full test suite

**Client-Facing Verification Report (Single Command)**

```bash
bash documents/setup_and_run/generate_client_report.sh
```

Output:
- markdown report: `documents/reports/client_exec_readout_YYYYMMDD_HHMMSS.md`
- raw run artifacts: `documents/reports/artifacts_YYYYMMDD_HHMMSS/`
- report now embeds full raw check outputs (including LLM proxy response bodies)

---

**Admin Policy Updates**

```bash
curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"action":"LOG_ONLY","changed_by":"admin"}'
```

Policy and entitlement changes are versioned in PostgreSQL when connected.

---

**Testing**

Run the full test suite:

```bash
python -m pytest -q
```

Note: Unit tests are mocked and do not call OpenAI or Cyren directly.
When `ADMIN_AUTH_ENABLED=true`, `/audit/log`, `/audit/events`, and `/audit/metrics*` require `x-admin-key`.

---

**Verification (Real Calls)**

- End-to-end verification: `tests/phase1_verify.sh`
- OpenAI-only check: `documents/setup_and_run/openai_gateway_test.sh`
- PowerShell version: `documents/setup_and_run/phase1_verify.ps1`

These scripts rebuild containers, run health checks, validate PII policy behavior, execute tests, and perform real OpenAI and Cyren calls. OpenAI requires a key with active quota.

**Runbook**

- Local/VPS operations runbook: `documents/runbook.md`
- Production baseline checklist: enable `ADMIN_AUTH_ENABLED=true`, set `ADMIN_API_KEY`, set strong `JWT_SECRET`, and set explicit CORS origins.

---

**Configuration (.env)**

```bash
# Server
HOST=0.0.0.0
PORT=8000
WORKERS=1
LOG_LEVEL=INFO
UPSTREAM_TIMEOUT_SECONDS=60.0
TRUST_PROXY_HEADERS=false

# CORS
CORS_ALLOWED_ORIGINS=http://localhost,http://127.0.0.1
CORS_ALLOWED_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=*
CORS_ALLOW_CREDENTIALS=false

# LLM Target
LLM_PROVIDER=openai
LLM_ENDPOINT=https://api.openai.com
LLM_API_KEY=
OPENAI_ENDPOINT=https://api.openai.com
OPENAI_API_KEY=
ANTHROPIC_ENDPOINT=https://api.anthropic.com
ANTHROPIC_API_KEY=
ANTHROPIC_API_VERSION=2023-06-01
GEMINI_ENDPOINT=https://generativelanguage.googleapis.com
GEMINI_API_KEY=
OPENROUTER_ENDPOINT=https://openrouter.ai/api/v1
OPENROUTER_API_KEY=

# Cyren + CTAS
CYREN_IPREP_URL=https://try-now-ipreputation.data443.io/ctipd/iprep
CYREN_URLF_URL=https://try-now-urlcat.data443.io/ctwsd/websec
CYREN_API_KEY=
CYREN_TIMEOUT=5.0
CYREN_RETRY_ATTEMPTS=2
CTAS_URL=https://try-now-antispam.data443.io/ctasd/ClassifyMessage_Inline
CTAS_TIMEOUT=5.0

# Redis Cache
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=
REDIS_L1_TTL=300
REDIS_L2_TTL=3600

# PostgreSQL Audit Log
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=data443_audit
POSTGRES_USER=postgres
POSTGRES_PASSWORD=
AUDIT_RETENTION_DAYS=30
AUDIT_MASK_SENSITIVE_FIELDS=true
AUDIT_REDACT_MESSAGE_CONTENT=false
AUDIT_MAX_STRING_LENGTH=4000

# Policy Thresholds
ALLOW_THRESHOLD=80
ALLOW_LOG_THRESHOLD=50
CONSTRAIN_THRESHOLD=20

# Circuit Breaker
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60

# JWT Authentication (Optional)
JWT_ENABLED=false
JWT_SECRET=your-secret-key-change-in-production
JWT_ISSUER=data443-gateway
JWT_AUDIENCE=data443-gateway

# Admin API Authentication (Optional)
ADMIN_AUTH_ENABLED=false
ADMIN_API_KEY=

# Agent Governance Hardening
AGENT_LINK_ENFORCEMENT_ENABLED=true
AGENT_INTERACTION_RETENTION_DAYS=30

# OpenTelemetry (Optional)
OTEL_ENABLED=false
OTEL_SERVICE_NAME=data443-llm-gateway
OTEL_EXPORTER_OTLP_ENDPOINT=
OTEL_EXPORTER_TIMEOUT_SECONDS=5.0
```

---

**API Endpoints**

Public:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | `GET` | Gateway information |
| `GET /health` | `GET` | Health check and component status |
| `GET /audit/log` | `GET` | Query audit log |
| `GET /audit/events` | `GET` | Query structured gateway events |
| `GET /audit/metrics` | `GET` | Query gateway telemetry snapshot (JSON) |
| `GET /audit/metrics/prometheus` | `GET` | Query gateway telemetry in Prometheus format |
| `POST /agents/{agent_id}/v1/chat/completions` | `POST` | Managed-agent proxy path |
| `* /{path:path}` | `ANY` | Proxy to target LLM endpoint |

Admin:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /admin/policies` | `GET` | List all policies |
| `GET /admin/policies/pii` | `GET` | Get PII detection policy |
| `PUT /admin/policies/pii` | `PUT` | Update PII detection policy |
| `GET /admin/policies/jailbreak` | `GET` | Get jailbreak policy |
| `PUT /admin/policies/jailbreak` | `PUT` | Update jailbreak policy |
| `GET /admin/policies/injection` | `GET` | Get injection policy |
| `PUT /admin/policies/injection` | `PUT` | Update injection policy |
| `GET /admin/policies/semantic` | `GET` | Get semantic detection policy |
| `PUT /admin/policies/semantic` | `PUT` | Update semantic detection policy |
| `GET /admin/policies/domain-risk` | `GET` | Get domain risk scoring policy |
| `PUT /admin/policies/domain-risk` | `PUT` | Update domain risk scoring policy |
| `GET /admin/policies/email-classification` | `GET` | Get email classification policy |
| `PUT /admin/policies/email-classification` | `PUT` | Update email classification policy |
| `GET /admin/policies/jwt` | `GET` | Get JWT auth policy |
| `PUT /admin/policies/jwt` | `PUT` | Update JWT auth policy |
| `GET /admin/policies/{name}/versions` | `GET` | List policy versions |
| `POST /admin/policies/{name}/rollback` | `POST` | Rollback to previous policy version |
| `GET /admin/entitlements` | `GET` | Get entitlement configuration |
| `PUT /admin/entitlements` | `PUT` | Update entitlement configuration |
| `POST /admin/agents/create` | `POST` | Create or update managed agent |
| `POST /admin/agents/wrap` | `POST` | Wrap external agent into control plane |
| `GET /admin/agents` | `GET` | List managed agents |
| `GET /admin/agents/{agent_id}` | `GET` | Get managed agent details |
| `POST /admin/agents/link` | `POST` | Create/update A2A link between agents |
| `GET /admin/agents/links` | `GET` | List A2A links |
| `POST /admin/a2a/interactions` | `POST` | Create A2A interaction |
| `GET /admin/a2a/interactions` | `GET` | List A2A interactions |
| `GET /admin/a2a/interactions/{interaction_id}` | `GET` | Get A2A interaction |
| `POST /admin/a2a/interactions/{interaction_id}/approve` | `POST` | Approve A2A interaction |
| `POST /admin/a2a/interactions/{interaction_id}/block` | `POST` | Block A2A interaction |
| `POST /admin/interactions/{request_id}/approve` | `POST` | Mark interaction as approved |
| `POST /admin/interactions/{request_id}/block` | `POST` | Mark interaction as blocked |
| `GET /admin/interactions/{request_id}` | `GET` | Get interaction review status |
| `DELETE /admin/policies/{name}` | `DELETE` | Delete a policy |
| `POST /admin/policies/reset` | `POST` | Reset all policies |

---

**Project Structure**

```
data443-llm-gateway/
  gateway/
    main.py
    api/
      public.py
      admin.py
      agent_control.py
    core/
      config.py
      logging.py
      types.py
    services/
      proxy_service.py
      policy_service.py
      content_filter.py
      jwt_auth.py
      agent_registry.py
    integrations/
      cyren_client.py
      cache.py
      audit.py
      telemetry.py
      event_schema.py
    policy/
      store.py
    providers/
      base.py
      router.py
      openai_provider.py
      anthropic_provider.py
      gemini_provider.py
      openrouter_provider.py
  tests/
    test_gateway.py
    test_phase2_policy_store.py
    test_phase2_provider_adapters.py
    test_phase2_observability_and_governance.py
    test_phase3_agent_control.py
    test_phase3_agent_proxy.py
    test_phase3_agent_registry_hardening.py
    phase1_verify.sh
  documents/
    setup_and_run/
      phase2_verify.sh
      generate_client_report.sh
  tools/
    redteam_prompts.jsonl
    redteam_runner.py
  config/
    settings.py  # compatibility shim
  docker-compose.yml
  Dockerfile
  requirements.txt
  pytest.ini
  .env (create this)
```

---

**Performance and Security Notes**
- Cached decisions target sub-10ms latency
- Circuit breaker prevents Cyren outages from blocking requests
- Every decision is auditable and immutable in PostgreSQL
- No LLM involved in security decisions
- Admin API key auth is available via `ADMIN_AUTH_ENABLED=true`

---

**License**

Data443 - All rights reserved.








