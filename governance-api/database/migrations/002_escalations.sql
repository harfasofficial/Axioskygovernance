-- database/migrations/002_escalations.sql
-- Escalations table for human-in-the-loop workflow

CREATE TABLE IF NOT EXISTS escalations (
    id BIGSERIAL PRIMARY KEY,
    escalation_id UUID NOT NULL UNIQUE,
    tenant_id VARCHAR(255) NOT NULL,
    decision_id UUID NOT NULL,
    agent_id VARCHAR(255) NOT NULL,
    action_type VARCHAR(255) NOT NULL,
    reason TEXT,
    reason_code VARCHAR(50),
    rule_triggered VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    webhook_url VARCHAR(2048),
    expires_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolved_by VARCHAR(255),
    action_on_expiry VARCHAR(20) DEFAULT 'BLOCK',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_esc_tenant_status
ON escalations (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_esc_decision
ON escalations (decision_id);

CREATE INDEX IF NOT EXISTS idx_esc_expires_pending
ON escalations (expires_at)
WHERE status = 'pending';
