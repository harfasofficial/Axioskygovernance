# audit/models.py
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AuditEntry:
    """
    Represents one row in the audit_log table.
    Created by the Governor, written by the AuditService.
    """
    decision_id: str
    tenant_id: str
    agent_id: str
    action_type: str
    status: str            # APPROVE | BLOCK | ESCALATE
    environment: str       # shadow | production
    reason: Optional[str]
    reason_code: Optional[str]
    rule_triggered: Optional[str]
    policy_version: Optional[str]
    latency_ms: Optional[int]

    # Computed by AuditService, not provided by the caller:
    payload_hash: str = field(default='')
    decision_hash: str = field(default='')
    previous_hash: Optional[str] = field(default=None)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
