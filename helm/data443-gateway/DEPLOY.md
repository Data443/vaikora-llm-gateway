# Data443 LLM Security Gateway — Helm Deployment Guide

## Prerequisites

- Kubernetes 1.24+
- Helm 3.x
- Container image built and pushed to a registry accessible from the cluster

## Quick Start

```bash
# Add Bitnami repo for PostgreSQL + Redis sub-charts
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install with required values
helm install data443-gw ./helm/data443-gateway \
  --set postgresql.auth.password=<STRONG_PG_PASSWORD> \
  --set redis.auth.password=<STRONG_REDIS_PASSWORD> \
  --set gateway.proxyApiKey=<PROXY_API_KEY> \
  --set gateway.admin.apiKey=<ADMIN_API_KEY>
```

## Required Values

| Value | Description | Example |
|-------|-------------|---------|
| `postgresql.auth.password` | PostgreSQL password for the audit database | `my-pg-secret-123` |
| `redis.auth.password` | Redis password for caching layer | `my-redis-secret-456` |
| `gateway.proxyApiKey` | API key callers must send via `x-api-key` header | `gw_abc123...` |
| `gateway.admin.apiKey` | Admin API key for `/admin/*` and audit/metrics endpoints when admin auth is enabled | `adm_abc123...` |

## Vaikora Control Plane Integration

To enable policy sync, audit federation, and HITL approvals with a Vaikora instance:

| Value | Description | Example |
|-------|-------------|---------|
| `gateway.controlPlane.enabled` | Enable integration | `true` |
| `gateway.controlPlane.url` | Vaikora backend URL | `http://vaikora-backend:8000` |
| `gateway.controlPlane.apiKey` | Vaikora API key (from Settings → API Key) | `vk_abc123...` |

```bash
helm install data443-gw ./helm/data443-gateway \
  --set postgresql.auth.password=<PG_PASSWORD> \
  --set redis.auth.password=<REDIS_PASSWORD> \
  --set gateway.proxyApiKey=<PROXY_KEY> \
  --set gateway.controlPlane.enabled=true \
  --set gateway.controlPlane.url=http://vaikora-backend:8000 \
  --set gateway.controlPlane.apiKey=<VAIKORA_API_KEY>
```

## Using External PostgreSQL / Redis

If you already have PostgreSQL or Redis running in the cluster:

```bash
helm install data443-gw ./helm/data443-gateway \
  --set postgresql.enabled=false \
  --set externalPostgresql.enabled=true \
  --set externalPostgresql.host=my-pg-host \
  --set externalPostgresql.password=<PG_PASSWORD> \
  --set redis.enabled=false \
  --set externalRedis.enabled=true \
  --set externalRedis.host=my-redis-host \
  --set externalRedis.password=<REDIS_PASSWORD> \
  --set gateway.proxyApiKey=<PROXY_KEY>
```

## Ingress

To expose the gateway via an Ingress controller (e.g., HAProxy):

```bash
helm install data443-gw ./helm/data443-gateway \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=gateway.yourdomain.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix \
  ...
```

## All Configurable Values

### Server Settings

| Value | Default | Description |
|-------|---------|-------------|
| `replicaCount` | `1` | Number of gateway replicas |
| `gateway.logLevel` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `gateway.logFormat` | `json` | Log format (`text` or `json`) |
| `gateway.workers` | `2` | Uvicorn worker processes |
| `gateway.upstreamTimeoutSeconds` | `60` | Timeout for upstream LLM calls |
| `gateway.trustProxyHeaders` | `true` | Trust X-Forwarded-For headers |
| `gateway.strictStartupValidation` | `true` | Fail fast on insecure/invalid startup config |

### Authentication

| Value | Default | Description |
|-------|---------|-------------|
| `gateway.proxyApiKeyEnabled` | `true` | Require x-api-key on proxy endpoints |
| `gateway.proxyApiKey` | `""` | **REQUIRED** — the API key value |
| `gateway.admin.authEnabled` | `true` | Require auth for admin endpoints |
| `gateway.admin.apiKey` | `""` | Admin API key |
| `gateway.jwt.enabled` | `false` | Enable JWT auth |
| `gateway.jwt.secret` | `""` | JWT signing secret |

### Rate Limiting

| Value | Default | Description |
|-------|---------|-------------|
| `gateway.rateLimit.enabled` | `true` | Enable rate limiting |
| `gateway.rateLimit.windowSeconds` | `60` | Rate limit window |
| `gateway.rateLimit.proxyRequests` | `120` | Max proxy requests per window |

### Cyren Threat Intelligence

| Value | Default | Description |
|-------|---------|-------------|
| `gateway.cyren.apiKey` | `""` | Cyren API key |
| `gateway.cyren.failClosed` | `true` | Block when Cyren unreachable |

### Control Plane (Vaikora)

| Value | Default | Description |
|-------|---------|-------------|
| `gateway.controlPlane.enabled` | `false` | Enable Vaikora integration |
| `gateway.controlPlane.url` | `""` | Vaikora backend URL |
| `gateway.controlPlane.apiKey` | `""` | Vaikora API key (`vk_...`) |
| `gateway.controlPlane.policySyncIntervalSeconds` | `60` | Policy pull interval |
| `gateway.controlPlane.auditPushIntervalSeconds` | `30` | Audit push interval |
| `gateway.controlPlane.hitlTimeoutSeconds` | `300` | HITL approval timeout |

### Database

| Value | Default | Description |
|-------|---------|-------------|
| `postgresql.enabled` | `true` | Deploy PostgreSQL sub-chart |
| `postgresql.auth.password` | `""` | **REQUIRED** — PG password |
| `postgresql.auth.database` | `data443_audit` | Database name |
| `externalPostgresql.enabled` | `false` | Use external PG instead |
| `externalPostgresql.host` | `""` | External PG hostname |

### Cache

| Value | Default | Description |
|-------|---------|-------------|
| `redis.enabled` | `true` | Deploy Redis sub-chart |
| `redis.auth.password` | `""` | **REQUIRED** — Redis password |
| `externalRedis.enabled` | `false` | Use external Redis instead |
| `externalRedis.host` | `""` | External Redis hostname |

### Resources

| Value | Default | Description |
|-------|---------|-------------|
| `resources.requests.cpu` | `200m` | CPU request |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.cpu` | `1` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |

### Autoscaling

| Value | Default | Description |
|-------|---------|-------------|
| `autoscaling.enabled` | `false` | Enable HPA |
| `autoscaling.minReplicas` | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | `5` | Maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | `70` | CPU target for scaling |

## Health and Readiness

The gateway exposes:
- `GET /health`: component-level liveness/diagnostics
- `GET /ready`: strict readiness probe for Kubernetes rollouts

`GET /health` returns:

```json
{
  "status": "healthy",
  "components": {
    "cyren_circuit_breaker": "closed",
    "redis_cache": "connected",
    "postgres_audit": "connected"
  }
}
```

The chart is configured to use:
- liveness probe: `/health`
- readiness probe: `/ready`
