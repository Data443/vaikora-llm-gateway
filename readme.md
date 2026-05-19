# Vaikora LLM Gateway

> Vaikora is an open-core AI runtime control gateway by Data443. Every AI agent action gets checked against deterministic policy before it executes, and every decision is signed into a SHA-256 audit chain. Compliance presets ship for SOC 2, HIPAA, GDPR, PCI DSS, and ISO 27001.

This repository hosts the reference gateway, MIT-licensed and self-hostable. The commercial Vaikora Control Plane (hosted by Data443) adds the audit chain, compliance presets, approvals UI, and vendor SLA. Visit [vaikora.com](https://vaikora.com/) for the hosted product.

## Quick facts

- **Category:** AI runtime control gateway, agent-to-agent (A2A) policy proxy
- **License:** MIT, free forever
- **Performance:** Sub-500ms p95 enforcement at the policy engine
- **Verdicts:** `ALLOW`, `ALLOW_LOG`, `CONSTRAIN`, `BLOCK`
- **LLM adapters:** OpenAI, Anthropic, Google Gemini, OpenRouter
- **Protocols:** HTTP, Model Context Protocol (MCP), Agent-to-Agent (A2A)
- **Content modules:** PII detection, jailbreak detection, prompt injection detection, semantic risk classification, domain risk scoring, email classification
- **Audit:** SHA-256 cryptographic append-only chain. Auditors can replay the chain end-to-end without vendor cooperation.
- **Compliance presets:** SOC 2 Type II, HIPAA, GDPR, PCI DSS, ISO 27001
- **Companion server:** [vaikora-guard-mcp](https://github.com/Data443/vaikora-guard-mcp) for MCP-aware AI clients
- **Hosted product:** [Vaikora Control Plane](https://vaikora.com/pricing) (quote-based, SaaS by Data443)
- **Distribution:** AWS Marketplace, Azure Sentinel, direct API
- **Parent company:** [Data443 Risk Mitigation, Inc.](https://data443.com/)

## What the gateway does

Vaikora sits between an AI agent and its downstream system (LLM, database, MCP tool, API). Every proposed action is intercepted, evaluated against the deterministic policy engine, and either allowed, allowed with a modification, logged, or blocked. The agent never reaches the downstream system until the gateway returns a verdict.

The engine is **deterministic**. The same input always returns the same decision, with the same audit receipt. There is no LLM judgement inside the policy path. This is what makes the audit chain admissible to compliance auditors.

## Where the gateway sits

```
AI Agent  ─►  Vaikora Gateway  ─►  LLM provider / MCP tool / database
                    │
                    ├─►  policy engine    (six content modules + custom rules)
                    ├─►  audit chain      (SHA-256 append-only)
                    ├─►  Slack OOB        (approvals queue for tier-3 actions)
                    └─►  receipt          (returned to caller for record-keeping)
```

## Vaikora is not

- A network firewall. Firewalls work at the packet layer. Vaikora works at the AI action layer.
- An endpoint security agent. Endpoint tools wrap user devices. Vaikora wraps AI traffic.
- A replacement for Azure RBAC, AWS IAM, or Snowflake roles. Vaikora adds a runtime gate on top of those identity controls.
- A guardrails library. Guardrails libraries run callbacks around an LLM call. Vaikora enforces deterministic policy on the proposed action and produces a tamper-proof audit receipt that an auditor can replay.

## Getting started

For a five-minute local run, jump to [Quick Start](#quick-start). For the hosted Control Plane (audit chain, compliance presets, SLA), contact sales at [vaikora.com/contact](https://vaikora.com/contact).

---

<div align="center">

<br/>

<img src="https://img.shields.io/badge/Data443-LLM%20Security%20Gateway-0a192f?style=for-the-badge&logo=shield&logoColor=38bdf8" height="42"/>

<br/><br/>

**Production-ready LLM reverse-proxy gateway for security, governance, and observability.**

The gateway sits in front of upstream LLM providers and enforces deterministic controls before any prompt reaches the model.

<br/>

![Build](https://img.shields.io/badge/Pytest-117%20Passed-22c55e?style=flat-square&logo=pytest&logoColor=white)
![Checks](https://img.shields.io/badge/Checks-46%20%2F%2049%20Passed-22c55e?style=flat-square&logo=checkmarx&logoColor=white)
![Skipped](https://img.shields.io/badge/Skipped-3%20Optional-f59e0b?style=flat-square)
![Status](https://img.shields.io/badge/Status-Operational-38bdf8?style=flat-square&logo=statuspage&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)

<br/>

</div>

---

## Current Build Status

| Metric | Result |
|--------|--------|
| Core gateway implementation | Complete and operational |
| Pytest suite | **117 passed** |
| Automated verification checks | **46 passed** / 3 skipped / 0 failed (49 total) |
| Security regression tests | **All 5 attack patterns blocked (403)** |
| OpenAI proxy flow | Verified and working |
| Managed-agent proxy flow | Verified and working |
| Optional provider checks | Skipped when API keys not configured (Anthropic, Gemini, OpenRouter) |

---

## What This System Does

This gateway protects and governs LLM traffic by:

- Intercepting requests/responses
- Enforcing policy and entitlement rules
- Applying deterministic security detection (6 content modules + 8 semantic categories)
- Routing to the selected provider via adapter pattern
- Writing immutable audit/event records
- Exposing JSON and Prometheus telemetry

Clients use one stable API surface, while operations get centralized security and full traceability.

---

## High-Level Architecture

```text
Client / App
    |
    v
+---------------------------------------------------+
|                Data443 LLM Gateway                |
|---------------------------------------------------|
| Middleware:                                       |
| - Rate Limiting (Redis / in-memory)               |
| - Request Body Size Limit (10 MB)                 |
| - CORS + GZip                                     |
|                                                   |
| Request pipeline:                                 |
| 0) Proxy API key auth (x-api-key header)          |
| 1) Optional JWT auth (mandatory exp claim)        |
| 2) Entitlements (provider/model/limits)           |
| 3) Content filter (PII/jailbreak/injection/       |
|    semantic/domain-risk/email-classification)      |
| 4) Cyren risk intelligence (IP + URL)             |
|    -> fail-closed when Cyren unavailable           |
| 5) Decision (ALLOW/ALLOW_LOG/CONSTRAIN/BLOCK)     |
| 6) Constraint engine (if CONSTRAIN)               |
| 7) A2A interaction enforcement (agent routes)     |
| 8) Provider adapter + upstream proxy              |
| 9) Response inspection                            |
| 10) Audit/events/telemetry emit                   |
+-----------------------------+---------------------+
                              |
                              v
       OpenAI / Anthropic / Gemini / OpenRouter
       (pooled httpx connections, 100 max)

Supporting stores:
- Redis 7 (L1/L2 cache, rate limit storage)
- PostgreSQL 15 (audit, versions, events, interactions)
- In-memory (L1 cache 10K cap, telemetry 500-key cap)
```

---

## Prompt Lifecycle (Step-by-Step)

When a user sends a prompt:

| Step | Action |
|:----:|--------|
| 1 | Request enters gateway endpoint |
| 2 | Rate limit + body size middleware checks |
| 3 | Proxy API key validated (if `PROXY_API_KEY_ENABLED=true`) |
| 4 | Gateway creates `request_id` and extracts context (IP, model, provider hint) |
| 5 | Optional JWT auth runs if enabled (requires valid `exp` claim) |
| 6 | Entitlements enforced -- provider enabled? model allowed? input/output limits within policy? |
| 7 | Content filter evaluates request text -- PII, jailbreak/injection, semantic abuse, domain risk, email classification |
| 8 | Cyren checks execute (IPRep and URLF) with cache and circuit breaker |
| 9 | Policy engine returns decision: ALLOW, ALLOW_LOG, CONSTRAIN, or BLOCK; **fail-closed** if Cyren unavailable |
| 10 | If blocked, gateway returns 403 with structured error |
| 11 | If constrained, gateway clamps tokens/temperature, injects safety prompt, redacts matches |
| 12 | For agent routes: A2A interaction ID validated as APPROVED (if `A2A_INTERACTION_ENFORCEMENT_ENABLED=true`) |
| 13 | Provider adapter transforms request and forwards upstream via pooled connection |
| 14 | Upstream response is normalized to OpenAI-compatible output shape |
| 15 | Response content is inspected again for policy violations |
| 16 | Gateway writes audit/event records and updates telemetry metrics |
| 17 | Final response is returned to the client |

---

## Decision Model

### Cyren Score Policy Thresholds

| Score Range | Result |
|:-----------:|:------:|
| 80 -- 100 | ALLOW |
| 50 -- 79 | ALLOW_LOG |
| 20 -- 49 | CONSTRAIN |
| 0 -- 19 | BLOCK |

### Content Policy Behavior

If request/response content matches enabled rules at or above severity threshold, configured action is enforced:

| Action | Description |
|--------|-------------|
| `BLOCK` | Request is rejected outright (HTTP 403) |
| `CONSTRAIN` | Request is modified and forwarded under constraint |
| `LOG_ONLY` | Request is logged and passed through unchanged |

### Semantic Detection Categories

All enabled by default with BLOCK action:

| Category | Catches |
|----------|---------|
| Policy Bypass | "ignore your rules", "bypass safety" |
| Prompt Exfiltration | "show system prompt", "print internal config and secrets" |
| Unrestricted Mode | "developer-debug mode", "god mode", "no filters" |
| Roleplay Bypass | "roleplay as unrestricted model" |
| Pentest Social Engineering | "authorized pentest", "assume I am authorized" |
| Sensitive Data Request | "list all customer records including passwords" |
| Encoding Bypass | "translate exactly", "base64 decode and execute" |
| Harmful Obfuscation | "for educational purposes" + exploit/malware intent |

---

## Key Capabilities

<details open>
<summary><strong>Security Controls</strong></summary>

<br/>

- PII detection: SSN, email, phone, credit card (Luhn), IP, passport, bank account
- Jailbreak/injection pattern checks (compiled regex)
- 8-category semantic abuse detector (policy bypass, exfiltration, unrestricted mode, roleplay, pentest, sensitive data, encoding bypass, harmful obfuscation)
- Domain-risk heuristic detection (suspicious TLDs, punycode, keywords)
- Email-risk/phishing intent classification
- JWT authentication with mandatory expiry
- Proxy API key authentication (`x-api-key` header for all proxy callers)
- Request body size limit (configurable, default 10 MB)
- Cyren fail-closed mode: blocks traffic when threat intelligence is unavailable

</details>

<details open>
<summary><strong>Governance Controls</strong></summary>

<br/>

- Versioned policies with rollback
- Versioned entitlements with module/provider/limit controls
- Admin auth hardening (`x-admin-key` + IP allowlist) when enabled
- Managed-agent registry and A2A interaction governance
- **A2A interaction enforcement**: every agent proxy call requires an APPROVED `x-a2a-interaction-id`
- Interaction review workflow (approve / block / get)
- Compliance defaults fully configurable at deployment (retention, masking, redaction)

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
- Pooled HTTP connections (100 max, 20 keep-alive)

</details>

<details open>
<summary><strong>Reliability and Observability</strong></summary>

<br/>

- Redis-backed two-level caching (L1 bounded to 10K entries, L2 in Redis)
- Circuit breaker around external threat-intel dependency
- Immutable PostgreSQL audit/event persistence
- Structured JSON logging (`LOG_FORMAT=json`) or human-readable text
- Metrics endpoints: JSON snapshot + Prometheus exposition
- Telemetry counters bounded to 500 distinct keys
- Optional OpenTelemetry tracing hooks
- Health endpoint with per-component status (Redis, Postgres, Cyren circuit breaker)

</details>

---

## API Surface

### Public Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Root |
| `GET` | `/health` | Health check (per-component status) |
| `GET` | `/ready` | Readiness probe (HTTP 200 when ready, HTTP 503 when degraded) |
| `GET` | `/audit/log` | Audit log query |
| `GET` | `/audit/events` | Gateway event stream |
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

## Quick Start

```bash
git clone https://github.com/Data443/data443-llm-gateway.git
cd data443-llm-gateway
cp .env.example .env
# Edit .env with your API keys and passwords
docker compose up -d --build
curl http://localhost:8000/health
```

---

## Configuration

Important environment variables:

| Category | Variables |
|----------|-----------|
| Server | `HOST`, `PORT`, `WORKERS`, `LOG_LEVEL`, `LOG_FORMAT`, `MAX_REQUEST_BODY_BYTES`, `STRICT_STARTUP_VALIDATION` |
| Rate Limiting | `RATE_LIMIT_ENABLED`, `RATE_LIMIT_STORAGE`, `RATE_LIMIT_PROXY_REQUESTS` |
| Provider | `LLM_PROVIDER`, `LLM_ENDPOINT`, `LLM_API_KEY` |
| Provider Keys | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` |
| Admin Auth | `ADMIN_AUTH_ENABLED`, `ADMIN_API_KEY`, `ADMIN_AUTH_MODE`, `ADMIN_ALLOWED_IPS` |
| JWT | `JWT_ENABLED`, `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE` |
| Thresholds | `ALLOW_THRESHOLD`, `ALLOW_LOG_THRESHOLD`, `CONSTRAIN_THRESHOLD` |
| Stores | Redis and PostgreSQL connection settings |
| Audit | `AUDIT_RETENTION_DAYS`, `AUDIT_MASK_SENSITIVE_FIELDS`, `AUDIT_REDACT_MESSAGE_CONTENT` |
| Cyren | `CYREN_IPREP_URL`, `CYREN_URLF_URL`, `CYREN_API_KEY`, `CYREN_FAIL_CLOSED` |
| Proxy Auth | `PROXY_API_KEY_ENABLED`, `PROXY_API_KEY` |
| Agent Governance | `AGENT_LINK_ENFORCEMENT_ENABLED`, `A2A_INTERACTION_ENFORCEMENT_ENABLED`, `AGENT_INTERACTION_RETENTION_DAYS` |
| Telemetry | `OTEL_ENABLED`, `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT` |

Production recommendation:
- Set `STRICT_STARTUP_VALIDATION=true` so the gateway fails fast on insecure/invalid startup config.

---

## Testing and Verification

### 1. Full automated verification (recommended)

```bash
bash tests/run_all_tests.sh
```

Runs Docker rebuild/start, health checks, pytest, API/governance checks, provider optional checks, and summary.

### 2. Live interactive LLM testing through gateway

```bash
LIVE_SHOW_RAW=true bash tests/live_gateway_console.sh
```

### 3. Pytest only

```bash
python -m pytest tests/ -v
```

### 4. Security regression tests

```bash
python -m pytest tests/py/test_rate_limit_and_semantic.py -v -k "semantic_blocks"
```

Validates that all 5 previously-200 attack patterns now return 403.

---

## Project Structure

```text
data443-llm-gateway/
  gateway/
    api/            # admin, agent_control, auth, public routes
    core/           # config, logging, types
    integrations/   # audit, cache, cyren_client, telemetry, otel, migrations
    middleware/     # rate_limit
    migrations/     # SQL schema files
    policy/         # store (versioned policies + entitlements)
    providers/      # base, router, openai, anthropic, gemini, openrouter
    services/       # proxy_service, content_filter, semantic_detector,
                    #   domain_risk_detector, email_classifier,
                    #   jwt_auth, policy_service, agent_registry
    main.py         # FastAPI app entry point
  tests/
    py/             # pytest test files
    sh/             # shell-based test scripts
    run_all_tests.sh
    live_gateway_console.sh
    live_gateway_console_strict.sh
  config/
  docker-compose.yml
  docker-compose.prod.yml
  Dockerfile
  requirements.txt
  pytest.ini
  .env
```

---

## Production Baseline Checklist

- [x] Cyren fail-closed mode: `CYREN_FAIL_CLOSED=true` (blocks when Cyren unavailable)
- [x] Proxy API key auth: `PROXY_API_KEY_ENABLED=true` and set strong `PROXY_API_KEY`
- [x] A2A interaction enforcement: `A2A_INTERACTION_ENFORCEMENT_ENABLED=true`
- [x] Compliance defaults configurable at deployment (retention, masking, redaction)
- [ ] Enable admin auth: `ADMIN_AUTH_ENABLED=true` and set strong `ADMIN_API_KEY`
- [ ] Enable JWT where required and set strong `JWT_SECRET`
- [ ] Set `POSTGRES_PASSWORD`; set `REDIS_PASSWORD` only when Redis AUTH is enabled (optional when Redis has no password)
- [ ] Set explicit `CORS_ALLOWED_ORIGINS` (no wildcard with credentials)
- [ ] Configure required provider API keys
- [ ] Use production overlay: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
- [ ] Set `LOG_FORMAT=json` for structured log aggregation
- [ ] Monitor `/health` endpoint and Prometheus metrics

---

<div align="center">

<br/>

**Released under the MIT License.**

<br/>

![Data443](https://img.shields.io/badge/Data443-Security%20%26%20Governance-0a192f?style=for-the-badge&logoColor=38bdf8)

</div>
