CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decision VARCHAR(20) NOT NULL,
    ip_address INET,
    url TEXT,
    risk_score INTEGER,
    ip_risk_score INTEGER,
    url_category INTEGER,
    user_agent TEXT,
    request_id TEXT,
    request_method TEXT,
    request_path TEXT,
    request_body JSONB,
    response_status INTEGER,
    response_time_ms INTEGER,
    reason TEXT,
    cyren_ref_id TEXT,
    CONSTRAINT valid_decision CHECK (decision IN ('ALLOW', 'ALLOW_LOG', 'CONSTRAIN', 'BLOCK', 'ERROR'))
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_log_ip_address ON audit_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_log_url ON audit_log USING HASH(url);

CREATE TABLE IF NOT EXISTS policy_versions (
    id BIGSERIAL PRIMARY KEY,
    policy_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    change_note TEXT,
    UNIQUE(policy_name, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_name_version
    ON policy_versions(policy_name, version DESC);

CREATE TABLE IF NOT EXISTS entitlement_versions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    version INTEGER NOT NULL,
    entitlements JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    change_note TEXT,
    UNIQUE(tenant_id, version)
);

CREATE INDEX IF NOT EXISTS idx_entitlement_versions_tenant_version
    ON entitlement_versions(tenant_id, version DESC);

CREATE TABLE IF NOT EXISTS llm_gateway_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id TEXT NOT NULL,
    decision VARCHAR(20) NOT NULL,
    risk_score INTEGER,
    ip_address INET,
    url TEXT,
    model TEXT,
    org_id TEXT,
    user_id TEXT,
    response_status INTEGER,
    response_time_ms INTEGER,
    reason TEXT,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_gateway_events_timestamp
    ON llm_gateway_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_gateway_events_request_id
    ON llm_gateway_events(request_id);
CREATE INDEX IF NOT EXISTS idx_gateway_events_decision
    ON llm_gateway_events(decision);

CREATE TABLE IF NOT EXISTS interaction_reviews (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    review_status VARCHAR(20) NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_by TEXT,
    reason TEXT,
    source_event_id BIGINT,
    source_decision VARCHAR(20),
    source_risk_score INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT valid_review_status CHECK (review_status IN ('APPROVED', 'BLOCKED'))
);

CREATE INDEX IF NOT EXISTS idx_interaction_reviews_reviewed_at
    ON interaction_reviews(reviewed_at DESC);

CREATE TABLE IF NOT EXISTS managed_agents (
    id BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    wrapped BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    updated_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_managed_agents_status
    ON managed_agents(status);

CREATE TABLE IF NOT EXISTS agent_links (
    id BIGSERIAL PRIMARY KEY,
    source_agent_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'A2A',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    updated_by TEXT,
    UNIQUE(source_agent_id, target_agent_id, protocol)
);

CREATE INDEX IF NOT EXISTS idx_agent_links_source
    ON agent_links(source_agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_links_target
    ON agent_links(target_agent_id);

CREATE TABLE IF NOT EXISTS agent_interactions (
    id BIGSERIAL PRIMARY KEY,
    interaction_id TEXT NOT NULL UNIQUE,
    source_agent_id TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    review_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    decision_reason TEXT,
    reviewed_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_agent_interaction_review_status
        CHECK (review_status IN ('PENDING', 'APPROVED', 'BLOCKED'))
);

CREATE INDEX IF NOT EXISTS idx_agent_interactions_source
    ON agent_interactions(source_agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_interactions_target
    ON agent_interactions(target_agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_interactions_status
    ON agent_interactions(review_status);
