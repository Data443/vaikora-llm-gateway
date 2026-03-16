# Data443 LLM Security Gateway

A reverse proxy security gateway that sits between users/AI agents and any LLM endpoint (OpenAI, Claude, etc). Every request is intercepted, evaluated, and either ALLOWED, BLOCKED, or CONSTRAINED before reaching the LLM.

## Features

- **Traffic Interception**: Intercept, normalize, and authenticate LLM API requests
- **Policy Evaluation**: ALLOW / BLOCK / CONSTRAIN decisions based on threat intelligence
- **Cyren Integration**: URL classification and IP reputation with aggressive caching
- **Two-Level Caching**: Redis L1/L2 caching for sub-10ms decision latency
- **Immutable Audit Log**: Every decision logged with full context in PostgreSQL
- **Circuit Breaker**: Fail-safe fallback when Cyren is unavailable
- **Fully Deterministic**: No LLM in the decision path

## Architecture

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│   Client    │────▶│  LLM Security       │────▶│   LLM API   │
│             │     │  Gateway           │     │  (OpenAI)   │
└─────────────┘     │  ┌───────────────┐  │     └─────────────┘
                    │  │ Policy Engine │  │
                    │  └───────────────┘  │
                    │  ┌───────────────┐  │
                    │  │ Cyren API     │  │
                    │  │ (Threat Intel)│  │
                    │  └───────────────┘  │
                    └─────────────────────┘
                          ▲         ▲
                          │         │
                    ┌─────┴─────┐ ┌─┴─────┐
                    │   Redis   │ │Postgres│
                    │  (Cache)  │ │ (Audit)│
                    └───────────┘ └────────┘
```

## Decision Logic

| Cyren Score | Trust Level | Action |
|-------------|-------------|--------|
| 80-100 | HIGH | ALLOW |
| 50-79 | MEDIUM | ALLOW with logging |
| 20-49 | LOW | CONSTRAIN |
| 0-19 | CRITICAL | BLOCK |

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone and navigate to the project
cd data443-llm-gateway

# Create .env file (see .env.example)
cp .env.example .env

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# View logs
docker-compose logs -f gateway
```

### Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# Start PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_DB=data443_audit \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  postgres:15-alpine

# Run the gateway
python -m gateway.main
```

## Configuration

Set environment variables in `.env`:

```bash
# Server
HOST=0.0.0.0
PORT=8000
LOG_LEVEL=INFO

# Cyren API
CYREN_IPREP_URL=https://try-now-ipreputation.data443.io/ctipd/iprep
CYREN_URLF_URL=https://try-now-urlcat.data443.io/ctwsd/websec
CYREN_API_KEY=your-api-key
CYREN_TIMEOUT=5.0

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=

# PostgreSQL
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=data443_audit
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

# Target LLM
LLM_ENDPOINT=https://api.openai.com/v1
LLM_API_KEY=your-openai-api-key

# Policy thresholds
ALLOW_THRESHOLD=80
ALLOW_LOG_THRESHOLD=50
CONSTRAIN_THRESHOLD=20
```

## Usage

### Proxying LLM Requests

Change your LLM API endpoint from:
```
https://api.openai.com/v1
```

To:
```
http://localhost:8000
```

The gateway will automatically:
1. Intercept the request
2. Evaluate policy using Cyren threat intelligence
3. Forward if ALLOWED, return error if BLOCKED
4. Log the decision to PostgreSQL

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Gateway information |
| `GET /health` | Health check and component status |
| `GET /audit/log` | Query audit log (filter by decision, IP, etc.) |
| `*/*` | Proxy all other requests to LLM endpoint |

### Audit Log Query

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

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Code Structure

```
data443-llm-gateway/
├── gateway/
│   ├── main.py         # FastAPI server entry point
│   ├── proxy.py        # Request interception logic
│   ├── policy.py       # ALLOW/BLOCK/CONSTRAIN engine
│   ├── cyren_client.py # Cyren API integration
│   ├── cache.py        # Redis L1/L2 caching
│   └── audit.py        # PostgreSQL audit logging
├── config/
│   └── settings.py     # Environment configuration
├── tests/
│   └── test_gateway.py # Unit tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Performance

- **Target p99 latency**: <10ms for cached requests
- **L1 Cache**: In-memory (300s TTL)
- **L2 Cache**: Redis (3600s TTL)
- **Circuit Breaker**: Auto-fallback when Cyren is unavailable

## Security

- **Fail-safe**: If gateway has issues, defined fallback behavior
- **Immutable Audit**: Every decision logged with full context
- **No LLM in Decision Path**: Fully deterministic security evaluation
- **Rate Limiting**: Optional constraint mode for suspicious requests

## License

Data443 - All rights reserved.
