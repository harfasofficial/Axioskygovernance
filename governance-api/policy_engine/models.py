# policy_engine/models.py
from pydantic import BaseModel
from typing import Optional, List, Any


class PolicyCondition(BaseModel):
    """A single condition within a rule."""
    field:    str     # The payload field to check, e.g. 'amount'
    operator: str     # gt, gte, lt, lte, eq, neq, in, not_in
    value:    Any     # The threshold or comparison value


class EscalationConfig(BaseModel):
    """Only present on ESCALATE rules."""
    target_role:      str   # e.g. 'chief_risk_officer'
    expires_minutes:  int   # How long before the escalation auto-expires
    action_on_expiry: str   # BLOCK or APPROVE if nobody responds


class PolicyRule(BaseModel):
    """
    One rule inside a policy template.
    Rules are evaluated in order. First match wins.
    If no rule matches: APPROVE.
    """
    rule_id:           str
    action_type:       str                        # Which action this rule applies to
    conditions:        List[PolicyCondition]      # ALL conditions must be true to trigger
    action:            str                        # APPROVE | BLOCK | ESCALATE
    reason:            str                        # Human-readable. Goes in audit log.
    reason_code:       str                        # Machine-readable. e.g. POLICY_001
    version:           str
    escalation_config: Optional[EscalationConfig] = None


class PolicyTemplate(BaseModel):
    """A full policy template containing multiple rules."""
    template_id:   str
    template_name: str
    version:       str
    description:   Optional[str] = None
    rules:         List[PolicyRule]


class PolicyResult(BaseModel):
    """
    What the engine returns after evaluation.
    This is what goes into the Governor response and eventually the audit log.
    """
    status:           str                        # APPROVE | BLOCK | ESCALATE
    rule_triggered:   Optional[str]   = None     # rule_id of the matched rule
    rules_evaluated:  List[str]       = []       # All rule_ids that were checked
    reason:           str             = 'all_policies_passed'
    reason_code:      str             = 'POLICY_OK'
    policy_version:   str             = 'default'
    escalation:       Optional[EscalationConfig] = None
