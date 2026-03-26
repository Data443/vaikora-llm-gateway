<div align="center">

<br/>

<img src="https://img.shields.io/badge/Data443-LLM%20Security%20Gateway-0a192f?style=for-the-badge&logo=shield&logoColor=38bdf8" height="42"/>

<br/><br/>

**Production-ready LLM reverse-proxy gateway for security, governance, and observability.**

The gateway sits in front of upstream LLM providers and enforces deterministic controls before any prompt reaches the model.

<br/>

![Build](https://img.shields.io/badge/Pytest-81%20Passed-22c55e?style=flat-square&logo=pytest&logoColor=white)
![Checks](https://img.shields.io/badge/Checks-46%20%2F%2049%20Passed-22c55e?style=flat-square&logo=checkmarx&logoColor=white)
![Skipped](https://img.shields.io/badge/Skipped-3%20Optional-f59e0b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Operational-38bdf8?style=flat-square&logo=statuspage&logoColor=white)
![License](https://img.shields.io/badge/License-Data443%20Proprietary-64748b?style=flat-square)

<br/>

</div>

---

## 📋 Current Build Status &nbsp;**

| Metric | Result |
|--------|--------|
| Core gateway implementation | ✅ Complete and operational |
| Pytest suite | ✅ **81 passed** |
| Automated verification checks | ✅ **46 passed** / 3 skipped / 0 failed (49 total) |
| OpenAI proxy flow | ✅ Verified and working |
| Managed-agent proxy flow | ✅ Verified and working |
| Optional provider checks | ⚠️ Skipped when API keys not configured (`Anthropic`, `Gemini`, `OpenRouter`) |

---

## 🔍 What This System Does

This gateway protects and governs LLM traffic by:

- intercepting requests/responses
- enforcing policy and entitlement rules
- applying deterministic security detection
- routing to the selected provider
- writing immutable audit/event records
- exposing JSON and Prometheus telemetry

This means clients use one stable API surface, while operations get centralized security and full traceability.

---

## 🏗 High-Level Architecture

```text
Client / App
    |
    v
+---------------------------------------------------+
|                Data443 LLM Gateway                |
|---------------------------------------------------|
| Ingress:                                          |
| - /v1/chat/completions                            |
| - /agents/{agent_id}/v1/chat/completions          |
|                                                   |
| Request pipeline:                                 |
| 1) Optional JWT auth                              |
| 2) Entitlements (provider/model/limits)           |
| 3) Content filter (PII/jailbreak/injection/...)   |
| 4) Cyren risk intelligence (IP + URL)             |
| 5) Decision (ALLOW/ALLOW_LOG/CONSTRAIN/BLOCK)     |
| 6) Provider adapter + upstream proxy              |
| 7) Response inspection                            |
| 8) Audit/events/telemetry emit                    |
+-----------------------------+---------------------+
                              |
                              v
       OpenAI / Anthropic / Gemini / OpenRouter

Supporting stores:
- Redis (L1/L2 cache path)
- PostgreSQL (audit, versions, events, interactions)
```

---

## 🔄 Prompt Lifecycle *(Step-by-Step)*

When a user sends a prompt:

| Step | Action |
|:----:|--------|
| 1 | Request enters gateway endpoint |
| 2 | Gateway creates `request_id` and extracts context (IP, model, provider hint) |
| 3 | Optional JWT auth runs if enabled |
| 4 | Entitlements are enforced — provider enabled? model allowed? input/output limits within policy? |
| 5 | Content filter evaluates request text — PII, jailbreak/injection, semantic abuse, domain risk, email-risk classification |
| 6 | Cyren checks execute (`IPRep` and `URLF`) with cache and circuit breaker |
| 7 | Policy engine returns decision: `ALLOW`, `ALLOW_LOG`, `CONSTRAIN`, or `BLOCK` |
| 8 | If blocked, gateway returns `403` with structured error |
| 9 | If allowed/constrained, provider adapter transforms request and forwards upstream |
| 10 | Upstream response is normalized to OpenAI-compatible output shape when required |
| 11 | Response content is inspected again for policy violations |
| 12 | Gateway writes audit/event records and updates telemetry metrics |
| 13 | Final response is returned to the client |

---

## ⚖️ Decision Model

### Cyren Score Policy Thresholds

| Score Range | Result |
|:-----------:|:------:|
| 80 – 100 | ✅ `ALLOW` |
| 50 – 79 | 📋 `ALLOW_LOG` |
| 20 – 49 | ⚠️ `CONSTRAIN` |
| 0 – 19 | 🚫 `BLOCK` |

### Content Policy Behavior

If request/response content matches enabled rules at or above severity threshold, configured action is enforced:

| Action | Description |
|--------|-------------|
| `BLOCK` | Request is rejected outright |
| `CONSTRAIN` | Request is modified and forwarded under constraint |
| `LOG_ONLY` | Request is logged and passed through unchanged |

---

## 🛡 Key Capabilities

<details open>
<summary><strong>Security Controls</strong></summary>

<br/>

- PII detection: SSN, email, phone, credit card (Luhn), IP, passport, bank account
- Jailbreak/injection pattern checks
- Semantic policy bypass / prompt exfiltration detection
- Domain-risk heuristic detection
- Email-risk/phishing intent classification
- Optional JWT request authentication

</details>

<details open>
<summary><strong>Governance Controls</strong></summary>

<br/>

- Versioned policies with rollback
- Versioned entitlements with module/provider/limit controls
- Admin auth hardening (`x-admin-key`) when enabled
- Managed-agent registry and A2A interaction governance
- Interaction review workflow (`approve` / `block` / `get`)

</details>

<details open>
<summary><strong>Provider Layer</strong></summary>

<br/>

- Provider router and adapters:
  - OpenAI
  - Anthropic
  - Gemini
  - OpenRouter
- Request/response normalization for cross-provider compatibility

</details>

<details open>
<summary><strong>Reliability + Observability</strong></summary>

<br/>

- Redis-backed two-level caching
- Circuit breaker around external threat-intel dependency
- Immutable PostgreSQL audit/event persistence
- Metrics endpoints:
  - JSON snapshot
  - Prometheus exposition
- Optional OpenTelemetry hooks

</details>

---

## 🌐 API Surface

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Root |
| `GET` | `/health` | Health check |
| `GET` | `/audit/log` | Audit log |
| `GET` | `/audit/events` | Audit events |
| `GET` | `/audit/metrics` | JSON metrics snapshot |
| `GET` | `/audit/metrics/prometheus` | Prometheus metrics exposition |
| `POST` | `/agents/{agent_id}/v1/chat/completions` | Managed-agent proxy |
| `ANY` | `/{path:path}` | Gateway proxy (catch-all) |

### Admin Endpoints

> Requires `x-admin-key` only when `ADMIN_AUTH_ENABLED=true`

- Policy CRUD + versioning + rollback
- Entitlement read/update
- Managed agent create/wrap/list/get
- A2A link and interaction create/list/get/review
- Interaction review endpoints (`/admin/interactions/{request_id}/...`)

---

## 🚀 Quick Start

```bash
git clone https://github.com/joseph88gomez/data443-llm-gateway.git
cd data443-llm-gateway
cp .env.example .env
docker-compose up -d --build
curl http://localhost:8000/health
```

---

## ⚙️ Configuration Notes

Important environment variables:

| Category | Variables |
|----------|-----------|
| Provider | `LLM_PROVIDER`, `LLM_ENDPOINT`, `LLM_API_KEY` |
| Provider Keys | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` |
| Admin Auth | `ADMIN_AUTH_ENABLED`, `ADMIN_API_KEY` |
| JWT | `JWT_ENABLED`, `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE` |
| Thresholds | `ALLOW_THRESHOLD`, `ALLOW_LOG_THRESHOLD`, `CONSTRAIN_THRESHOLD` |
| Stores | Redis and PostgreSQL connection settings |

> `CTAS_URL`/`CTAS_TIMEOUT` are present in config for extension scenarios.

---

## 🧪 Testing and Verification

Test layout is documented in [tests/README.md](tests/README.md).

### 1 · Full automated verification *(recommended)*

```bash
bash tests/run_all_tests.sh
```

Runs:
- Docker rebuild/start
- health checks
- pytest (`tests/py/test_*.py`)
- API/governance checks
- provider optional checks (if keys set)
- summary with pass/fail/skip

### 2 · Live interactive LLM testing through gateway

```bash
LIVE_SHOW_RAW=true bash tests/live_gateway_console.sh
```

Runs full verification first, then opens interactive prompt.

- Shows raw HTTP/JSON output (`LIVE_SHOW_RAW=true`)
- Can force live prompt even on verification failure with `ALLOW_LIVE_ON_FAIL=true`

### 3 · Pytest only

```bash
python -m pytest -q tests/py
```

---

## 📁 Project Structure

```text
data443-llm-gateway/
  gateway/
    api/
    core/
    integrations/
    policy/
    providers/
    services/
    main.py
  tests/
    README.md
    run_all_tests.sh
    live_gateway_console.sh
    py/
      test_all.py
    sh/
      all.sh
      live.sh
  config/
  docker-compose.yml
  Dockerfile
  requirements.txt
  pytest.ini
```

---

## ✅ Production Baseline Checklist

- [ ] Enable admin auth: `ADMIN_AUTH_ENABLED=true` and set `ADMIN_API_KEY`
- [ ] Enable JWT where required and set strong `JWT_SECRET`
- [ ] Set explicit `CORS_ALLOWED_ORIGINS` (no wildcard + credentials)
- [ ] Configure required provider API keys
- [ ] Keep audit/metrics endpoints protected in deployment
- [ ] Monitor Prometheus metrics and audit/event logs

---

<div align="center">

<br/>

**Data443 — All rights reserved.**

<br/>

![Data443](https://img.shields.io/badge/Data443-Security%20%26%20Governance-0a192f?style=for-the-badge&logoColor=38bdf8)

</div>