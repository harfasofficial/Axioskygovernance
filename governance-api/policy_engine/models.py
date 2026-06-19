# policy_engine/models.py
from pydantic import BaseModel
from typing import Optional, List, Any


class PolicyCondition(BaseModel):
    """A single condition within a rule."""
    field:    str     # The payload field to check, e.g. 'amount'
    operator: str     # gt, gte, lt, lte, eq, neq, in, not_in, contains, starts_with, ends_with
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
    If no rule matches: BLOCK (fail-closed).

    conditions: ALL must be true (AND logic)
    any_of:     AT LEAST ONE must be true (OR logic, optional)
    """
    rule_id:           str
    action_type:       str
    conditions:        List[PolicyCondition]       = []
    any_of:            Optional[List[PolicyCondition]] = None  # OR logic
    action:            str                        # APPROVE | BLOCK | ESCALATE
    reason:            str
    reason_code:       str
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
    Goes into the Governor response and audit log.
    """
    status:          str
    rule_triggered:  Optional[str]   = None
    rules_evaluated: List[str]       = []
    reason:          str             = 'no_policy_matched'
    reason_code:     str             = 'NO_POLICY_MATCHED'
    policy_version:  str             = 'default'
    escalation:      Optional[EscalationConfig] = None
