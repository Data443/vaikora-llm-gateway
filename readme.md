# Data443 LLM Security Gateway

Production-ready Phase 1 reverse-proxy security gateway for LLM endpoints. The gateway intercepts every request and response, evaluates deterministic security policies, and enforces ALLOW/BLOCK/CONSTRAIN decisions before traffic reaches the LLM.

---

**Status**
- Phase 1: Production-ready prototype complete
- Test suite: 33 tests passing
- End-to-end verification: OpenAI + Cyren IPRep/URLF confirmed

---

**Key Capabilities**
- Reverse-proxy traffic interception and normalization
- Optional JWT authentication on inbound requests
- PII detection (SSN, email, phone, credit card, IP, passport, bank account)
- Malicious prompt detection (jailbreak and injection patterns)
- Data443 Cyren IP reputation and URL classification
- Deterministic policy engine (no LLM in the decision path)
- L1 in-memory + L2 Redis caching for Cyren lookups
- Immutable audit log in PostgreSQL
- Circuit breaker for external dependency failures
- Admin API for hot policy updates
- JSON response inspection for policy enforcement

---

**Architecture (High Level)**

```
Client / AI Agent
        |
        v
+-------------------------------------------+
| Data443 LLM Security Gateway              |
|  - JWT Auth (optional)                    |
|  - Content Filter (PII/Jailbreak/Inject)  |
|  - Policy Engine (ALLOW/BLOCK/CONSTRAIN)  |
|  - Cache (L1/L2)                          |
|  - Audit Log                              |
+-------------------------------------------+
        |
        v
Target LLM Endpoint (OpenAI/Claude/Gemini/etc.)
```

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

**Admin Policy Updates (Phase 1)**

Policy updates require `policy_name` in the JSON body.

```bash
curl -X PUT http://localhost:8000/admin/policies/pii \
  -H "Content-Type: application/json" \
  -d '{"policy_name":"pii_detection","action":"LOG_ONLY"}'
```

Note: Policy storage is in-memory for Phase 1. For long-term production use, back this with Redis or a database.

---

**Testing**

Run the Phase 1 test suite (33 tests):

```bash
python -m pytest tests/test_gateway.py -q
```

Note: These tests are mocked and do not call OpenAI or Cyren.

---

**Verification (Real Calls)**

- End-to-end verification: `tests/phase1_verify.sh`
- OpenAI-only check: `documents/setup_and_run/openai_gateway_test.sh`
- PowerShell version: `documents/setup_and_run/phase1_verify.ps1`

These scripts rebuild containers, run health checks, validate PII policy behavior, execute tests, and perform real OpenAI and Cyren calls. OpenAI requires a key with active quota.

---

**Configuration (.env)**

```bash
# Server
HOST=0.0.0.0
PORT=8000
WORKERS=1
LOG_LEVEL=INFO

# LLM Target
LLM_ENDPOINT=https://api.openai.com
LLM_API_KEY=your-openai-api-key

# Data443 Cyren API (Trial Endpoints)
CYREN_IPREP_URL=https://try-now-ipreputation.data443.io/ctipd/iprep
CYREN_URLF_URL=https://try-now-urlcat.data443.io/ctwsd/websec
CYREN_API_KEY=
CYREN_TIMEOUT=5.0

# Redis Cache
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# PostgreSQL Audit Log
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=data443_audit
POSTGRES_USER=postgres
POSTGRES_PASSWORD=

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
```

---

**API Endpoints**

Public:
| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | Gateway information |
| `GET /health` | Health check and component status |
| `GET /audit/log` | Query audit log |
| `* /{path:path}` | Proxy to target LLM endpoint |

Admin:
| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /admin/policies` | List all policies |
| `GET /admin/policies/pii` | Get PII detection policy |
| `PUT /admin/policies/pii` | Update PII detection policy |
| `GET /admin/policies/jailbreak` | Get jailbreak policy |
| `PUT /admin/policies/jailbreak` | Update jailbreak policy |
| `GET /admin/policies/injection` | Get injection policy |
| `PUT /admin/policies/injection` | Update injection policy |
| `GET /admin/policies/jwt` | Get JWT auth policy |
| `PUT /admin/policies/jwt` | Update JWT auth policy |
| `DELETE /admin/policies/{name}` | Delete a policy |
| `POST /admin/policies/reset` | Reset all policies |

---

**Project Structure**

```
data443-llm-gateway/
  gateway/
    main.py
    api/
      public.py
      admin.py
    core/
      config.py
      logging.py
      types.py
    services/
      proxy_service.py
      policy_service.py
      content_filter.py
      jwt_auth.py
    integrations/
      cyren_client.py
      cache.py
      audit.py
  tests/
    test_gateway.py
    phase1_verify.sh
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
- Phase 1 Admin API is not authenticated; protect it via network controls

---

**License**

Data443 - All rights reserved.




