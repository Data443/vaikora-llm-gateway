# Data443 LLM Security Gateway

A production-grade reverse proxy security gateway for LLM endpoints. Intercepts, evaluates, and enforces security policies on all AI traffic before reaching the LLM.

---

## Features

| Feature | Description |
|----------|-------------|
| **Traffic Interception** | Intercept, normalize, and authenticate LLM API requests |
| **JWT Authentication** | Optional JWT token validation on incoming requests |
| **PII Detection** | Detects SSN, email, phone, credit card, IP, passport, bank accounts |
| **Malicious Prompt Detection** | Detects jailbreak attempts and injection attacks |
| **Data443 Integration** | IP reputation and URL classification via Cyren API |
| **Policy Engine** | Deterministic ALLOW/BLOCK/CONSTRAIN decisions (0-100 risk scoring) |
| **Two-Level Caching** | Redis L1/L2 caching for sub-10ms decision latency |
| **Immutable Audit Log** | Every decision logged with full context in PostgreSQL |
| **Circuit Breaker** | Fail-safe fallback when Cyren is unavailable |
| **Admin API** | Hot policy updates without gateway restart |
| **Multi-LLM Support** | Works with OpenAI, Claude, Gemini, and custom endpoints |
| **Fully Deterministic** | No LLM in decision path |

---

## Architecture

```
┌──────────────┐
│  Client/AI   │
│   Agent       │
└──────┬───────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│     Data443 LLM Security Gateway          │
│  ┌─────────────────────────────────────┐   │
│  │ JWT Auth │ Content │ Policy   │   │
│  │          │ Filter   │ Engine    │   │
│  └────┬─────┴────┬────┴─────┐   │
│       │            │           │       │
│       ▼            ▼           ▼       │
│  ┌────────┐  ┌─────────┐ ┌──────┐ │
│  │ Cache  │  │  Audit  │ │Cyren│ │
│  └────────┘  │  Log    │ │ API  │ │
│              └─────────┘ └──────┘ │
└───────────────┬───────────────────────┘
                │
                ▼
        ┌───────────────┐
        │ Target LLM    │
        │ (Any Provider) │
        └───────────────┘
```

---

## Decision Logic

| Cyren Score | Trust Level | Action |
|-------------|-------------|--------|
| 80-100 | HIGH | ALLOW |
| 50-79 | MEDIUM | ALLOW with logging |
| 20-49 | LOW | CONSTRAIN |
| 0-19 | CRITICAL | BLOCK |

---

## Quick Start with Docker

### Prerequisites
- Docker
- Docker Compose

### Start Services

```bash
# Clone repository
git clone https://github.com/joseph88gomez/data443-llm-gateway.git
cd data443-llm-gateway

# Create .env file
cp .env.example .env

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f gateway
```

### Expected Health Response

```json
{
  "status": "healthy",
  "circuit_breaker": "closed",
  "cache_connected": false,
  "audit_connected": false
}
```

---

## Configuration

Set environment variables in `.env`:

```bash
# Server Configuration
HOST=0.0.0.0
PORT=8000
WORKERS=1
LOG_LEVEL=INFO

# Target LLM Endpoint
LLM_ENDPOINT=https://api.openai.com/v1
LLM_API_KEY=your-openai-api-key

# Data443 Cyren API (Trial Endpoints)
CYREN_IPREP_URL=https://try-now-ipreputation.data443.io/ctipd/iprep
CYREN_URLF_URL=https://try-now-urlcat.data443.io/ctwsd/websec
CYREN_API_KEY=
CYREN_TIMEOUT=5.0

# Redis Cache (Optional - for L2 caching)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# PostgreSQL Audit Log (Optional)
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

## Supported LLM Providers

| Provider | Endpoint URL | Configuration |
|-----------|--------------|---------------|
| OpenAI | `https://api.openai.com/v1` | Default |
| Claude/Anthropic | `https://api.anthropic.com/v1` | Set `LLM_ENDPOINT` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1` | Set `LLM_ENDPOINT` |
| Cohere | `https://api.cohere.ai/v1` | Set `LLM_ENDPOINT` |
| Custom/Internal | Any HTTP endpoint | Set `LLM_ENDPOINT` |

---

## API Endpoints

### Public Endpoints

| Endpoint | Method | Description |
|----------|----------|-------------|
| `GET /` | Gateway information |
| `GET /health` | Health check and component status |
| `GET /audit/log` | Query audit log (limit, offset, decision, ip filters) |
| `* /{path:path}` | ALL | Proxy to target LLM endpoint |

### Admin API Endpoints

| Endpoint | Method | Description |
|----------|----------|-------------|
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
| `POST /admin/policies/reset` | Reset all policies to defaults |

---

## PII Detection Patterns

| Type | Pattern | Severity | Action |
|-------|----------|----------|--------|
| SSN | `XXX-XX-XXXX` | HIGH | BLOCK |
| Email | `user@example.com` | MEDIUM | LOG_ONLY / CONSTRAIN |
| Phone (US) | `XXX-XXX-XXXX` | MEDIUM | LOG_ONLY / CONSTRAIN |
| Credit Card | `XXXX-XXXX-XXXX-XXXX` | HIGH | BLOCK |
| IP Address | `XXX.XXX.XXX.XXX` | MEDIUM | LOG_ONLY / CONSTRAIN |
| Passport | `US12` | HIGH | BLOCK |
| Bank Account | US routing format | HIGH | BLOCK |

---

## Malicious Prompt Detection

| Type | Examples | Severity | Action |
|-------|-----------|----------|--------|
| Jailbreak | "Ignore previous instructions", "Act as different persona" | HIGH | BLOCK |
| Injection | "system:", "assistant:", prompt injection attempts | HIGH | BLOCK |

---

## Testing

### Test Health Endpoint

```bash
curl http://localhost:8000/health
```

### Test Gateway Root

```bash
curl http://localhost:8000/
```

### Test Admin Policies

```bash
curl http://localhost:8000/admin/policies
```

### Test PII Detection (Should be BLOCKED)

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"My SSN is 123-45-6789"}]}'
```

### Test Normal Request (Should be ALLOWED)

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_OPENAI_KEY" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello, how are you?"}]}'
```

### Test JWT Authentication

```bash
# Enable JWT auth
curl -X PUT http://localhost:8000/admin/policies/jwt \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"secret":"test-secret"}'

# Then request with JWT (token must be generated)
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}]}'
```

---

## Audit Log Query

```bash
# Get all audit logs
curl http://localhost:8000/audit/log

# Filter by decision
curl http://localhost:8000/audit/log?decision=BLOCK

# Filter by IP
curl http://localhost:8000/audit/log?ip=1.2.3.4

# Pagination
curl http://localhost:8000/audit/log?limit=50&offset=0
```

---

## Docker Services

| Service | Port | Description |
|---------|--------|-------------|
| gateway | 8000 | Main FastAPI application |
| redis | 6379 | L2 cache for API results |
| postgres | 5432 | Audit log database |

---

## Development

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Locally

```bash
# Start Redis (optional)
docker run -d -p 6379:6379 redis:7-alpine

# Start PostgreSQL (optional)
docker run -d -p 5432:5432 \
  -e POSTGRES_DB=data443_audit \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  postgres:15-alpine

# Run gateway
python -m gateway.main
```

### Run Tests

```bash
pytest tests/ -v
```

---

## Project Structure

```
data443-llm-gateway/
├── gateway/
│   ├── main.py              # FastAPI server entry point
│   ├── proxy.py             # Request interception & forwarding
│   ├── policy.py            # Policy engine & decision logic
│   ├── cyren_client.py      # Data443 API integration
│   ├── cache.py             # L1/L2 caching
│   ├── audit.py             # PostgreSQL audit logging
│   ├── jwt_auth.py         # JWT authentication
│   ├── content_filter.py    # PII & malicious prompt detection
│   └── admin_api.py         # Admin API for policy management
├── config/
│   └── settings.py         # Configuration management
├── tests/
│   └── test_gateway.py     # Unit tests
├── docker-compose.yml       # Docker orchestration
├── Dockerfile              # Container definition
├── requirements.txt         # Python dependencies
└── .env                   # Environment variables (create this)
```

---

## Performance

- **Target p99 latency**: <10ms for cached requests
- **L1 Cache**: In-memory (300s TTL)
- **L2 Cache**: Redis (3600s TTL)
- **Circuit Breaker**: Auto-fallback when Cyren is unavailable

---

## Security

- **Fail-safe**: If gateway has issues, defined fallback behavior
- **Immutable Audit**: Every decision logged with full context
- **No LLM in Decision Path**: Fully deterministic security evaluation
- **Rate Limiting**: Optional constraint mode for suspicious requests

---

## License

Data443 - All rights reserved.
