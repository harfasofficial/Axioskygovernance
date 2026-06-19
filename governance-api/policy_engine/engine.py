# policy_engine/engine.py
import operator
from typing import Dict, Any, List

from policy_engine.models import PolicyRule, PolicyResult, PolicyCondition


# -- Operator map ----------------------------------------------------------------
# These are the comparison operations a policy rule can use.
# Keeping this as a plain dict makes it easy to audit what operators exist.
OPS: Dict[str, Any] = {
    'gt':     operator.gt,          # field > value
    'gte':    operator.ge,          # field >= value
    'lt':     operator.lt,          # field < value
    'lte':    operator.le,          # field <= value
    'eq':     operator.eq,          # field == value
    'neq':    operator.ne,          # field != value
    'in':     lambda a, b: a in (b if isinstance(b, (list, tuple, set)) else [b]),
    'not_in': lambda a, b: a not in (b if isinstance(b, (list, tuple, set)) else [b]),
}


class PolicyEngine:
    """
    Deterministic rules engine.
    Input:  action_type, payload dict, list of PolicyRule objects
    Output: PolicyResult with APPROVE / BLOCK / ESCALATE

    Design: rules are evaluated in order. First rule whose ALL conditions
    match the payload is the decision. Remaining rules are skipped.
    If no rule matches: APPROVE with reason 'all_policies_passed'.
    """

    def evaluate(
        self,
        action_type: str,
        payload:     Dict[str, Any],
        rules:       List[PolicyRule],
    ) -> PolicyResult:
        """
        Main evaluation method.
        Called by the Governor for every incoming action.
        """
        evaluated_rule_ids: List[str] = []

        for rule in rules:
            # Only evaluate rules that match this action_type
            if rule.action_type != action_type:
                continue

            evaluated_rule_ids.append(rule.rule_id)

            # Check all conditions in this rule
            if self._all_conditions_match(rule.conditions, payload):
                # This rule triggered -- return immediately
                return PolicyResult(
                    status          = rule.action,
                    rule_triggered  = rule.rule_id,
                    rules_evaluated = evaluated_rule_ids,
                    reason          = rule.reason,
                    reason_code     = rule.reason_code,
                    policy_version  = rule.version,
                    escalation      = rule.escalation_config,
                )

        # No rule matched -- default APPROVE
        return PolicyResult(
            status          = 'APPROVE',
            rule_triggered  = None,
            rules_evaluated = evaluated_rule_ids,
            reason          = 'all_policies_passed',
            reason_code     = 'POLICY_OK',
            policy_version  = 'default',
        )

    def _all_conditions_match(
        self,
        conditions: List[PolicyCondition],
        payload:    Dict[str, Any],
    ) -> bool:
        """
        Returns True only if EVERY condition in the list matches the payload.
        If any condition fails, the whole rule does not trigger.
        This is AND logic: condition1 AND condition2 AND condition3...
        """
        for cond in conditions:
            payload_value = payload.get(cond.field)

            # Field missing from payload: condition cannot match
            if payload_value is None:
                return False

            op_fn = OPS.get(cond.operator)
            if op_fn is None:
                # Unknown operator: fail safe -- treat as non-matching
                return False

            try:
                if not op_fn(payload_value, cond.value):
                    return False  # This condition failed
            except (TypeError, ValueError):
                return False  # Type mismatch: fail safe

        return True  # All conditions passed


# Singleton -- one engine instance for the whole application
policy_engine = PolicyEngine()
