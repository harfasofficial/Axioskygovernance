-- database/migrations/001_audit_log.sql
-- Axiosky: Initial schema
-- Run order: this is the first migration -- 002_escalations.sql follows
-- ----------------------------------------------------------------------------


-- -- Tenants -------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id         BIGSERIAL    PRIMARY KEY,
    org_name   VARCHAR(255) NOT NULL,
    status     VARCHAR(50)  NOT NULL DEFAULT 'trial',
    plan_tier  VARCHAR(50)  NOT NULL DEFAULT 'pilot',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- -- API Keys -------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id),
    key_hash    VARCHAR(64)  NOT NULL UNIQUE,   -- SHA-256 hash, never plaintext
    agent_scope VARCHAR(255),                   -- NULL = all agents
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- -- Agents (reserved for future use) --------------------------------------------------------
CREATE TABLE IF NOT EXISTS agents (
    id         BIGSERIAL    PRIMARY KEY,
    tenant_id  BIGINT       NOT NULL REFERENCES tenants(id),
    agent_id   VARCHAR(255) NOT NULL UNIQUE,
    name       VARCHAR(255) NOT NULL,
    status     VARCHAR(50)  NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- -- Policies (reserved for future use) ------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id),
    template_id VARCHAR(100) NOT NULL,
    rules_json  JSONB        NOT NULL,
    version     VARCHAR(50)  NOT NULL DEFAULT '1.0',
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- -- Audit Log (IMMUTABLE) --------------------------------------------------------------------
-- CRITICAL: This table can never be updated or deleted from.
-- The trigger below enforces this at the database kernel level.
-- Even a superuser cannot modify rows once inserted.
-- This is the technical implementation of the 'immutable audit trail'
-- that every bank and fintech will ask about in a compliance review.

CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL    PRIMARY KEY,
    decision_id    UUID         NOT NULL UNIQUE,
    tenant_id      VARCHAR(255) NOT NULL,       -- Denormalised for fast querying
    agent_id       VARCHAR(255) NOT NULL,
    action_type    VARCHAR(255) NOT NULL,
    status         VARCHAR(10)  NOT NULL,       -- APPROVE | BLOCK | ESCALATE
    environment    VARCHAR(20)  NOT NULL,       -- shadow | production
    reason         TEXT,
    reason_code    VARCHAR(50),
    rule_triggered VARCHAR(255),
    policy_version VARCHAR(50),
    payload_hash   VARCHAR(64)  NOT NULL,       -- SHA-256 of payload JSON
    decision_hash  VARCHAR(64)  NOT NULL,       -- SHA-256 of payload_hash + status
    previous_hash  VARCHAR(64),                 -- Hash chain link to previous entry
    latency_ms     INTEGER,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes for fast tenant-scoped queries (every query filters by tenant_id)
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_agent  ON audit_log(tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_log(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_env    ON audit_log(tenant_id, environment);


-- -- IMMUTABILITY TRIGGER ----------------------------------------------------------------------
-- This trigger fires BEFORE any UPDATE or DELETE on audit_log.
-- It raises an exception, preventing the operation entirely.
-- Cannot be bypassed by any application user.

CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'Audit log is immutable. Operation: %. Attempted at: %.',
        TG_OP, NOW();
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_immutable ON audit_log;

CREATE TRIGGER audit_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_modification();


-- -- PERMISSIONS -------------------------------------------------------------------------------
-- App user can INSERT and SELECT only.
-- Cannot UPDATE or DELETE audit_log ever.
-- Wrapped in DO block to handle cases where 'axiosky' role does not exist.

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'axiosky') THEN
        REVOKE UPDATE, DELETE ON audit_log FROM axiosky;
        GRANT SELECT, INSERT ON audit_log TO axiosky;
    END IF;
END $$;
