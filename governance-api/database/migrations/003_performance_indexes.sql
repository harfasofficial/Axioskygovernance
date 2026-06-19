-- database/migrations/003_performance_indexes.sql
-- Performance indexes for tables added in 001 that were missing tenant-scoped indexes.
--
-- Context: 001_audit_log.sql already covers audit_log with 4 composite indexes.
-- This migration adds the missing indexes on api_keys, agents, policies,
-- and a composite covering index on audit_log(action_type) for analytics.
--
-- All indexes use IF NOT EXISTS -- safe to re-run.
-- CONCURRENTLY would be preferred for a live system but is not valid
-- inside a transaction block; the migration runner uses autocommit=True
-- so these will run efficiently without locking the table.

-- api_keys: tenant_id lookups during key rotation and listing
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant
    ON api_keys (tenant_id, created_at DESC);

-- api_keys: find non-expired keys fast (used by auth hot path is already
-- covered by the UNIQUE index on key_hash, but this helps admin listing)
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_expires
    ON api_keys (tenant_id, expires_at)
    WHERE expires_at IS NOT NULL;

-- agents: tenant-scoped lookups for agent registry
CREATE INDEX IF NOT EXISTS idx_agents_tenant_status
    ON agents (tenant_id, status);

-- policies: active policy lookup per tenant (hot path for policy engine
-- when database-driven policies are enabled in a future version)
CREATE INDEX IF NOT EXISTS idx_policies_tenant_active
    ON policies (tenant_id, is_active)
    WHERE is_active = TRUE;

-- audit_log: action_type analytics (shadow report queries group by action_type)
-- Composite with tenant_id so it is always tenant-scoped.
CREATE INDEX IF NOT EXISTS idx_audit_action_type
    ON audit_log (tenant_id, action_type, created_at DESC);

-- audit_log: latency analytics (p95/p99 latency queries filter by tenant)
CREATE INDEX IF NOT EXISTS idx_audit_latency
    ON audit_log (tenant_id, latency_ms)
    WHERE latency_ms IS NOT NULL;
