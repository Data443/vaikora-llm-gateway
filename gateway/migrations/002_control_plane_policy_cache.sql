CREATE TABLE IF NOT EXISTS control_plane_policy_cache (
    id BIGSERIAL PRIMARY KEY,
    organization_id TEXT,
    policies JSONB NOT NULL DEFAULT '[]'::jsonb,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_cp_policy_cache_synced_at
    ON control_plane_policy_cache(synced_at DESC);
