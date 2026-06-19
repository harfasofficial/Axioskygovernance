# policy_engine/engine.py
import operator
from typing import Dict, Any, List

from policy_engine.models import PolicyRule, PolicyResult, PolicyCondition


# -- Operator map ----------------------------------------------------------------
OPS: Dict[str, Any] = {
    'gt':       operator.gt,
    'gte':      operator.ge,
    'lt':       operator.lt,
    'lte':      operator.le,
    'eq':       operator.eq,
    'neq':      operator.ne,
    'in':       lambda a, b: a in (b if isinstance(b, (list, tuple, set)) else [b]),
    'not_in':   lambda a, b: a not in (b if isinstance(b, (list, tuple, set)) else [b]),
    'contains': lambda a, b: isinstance(a, str) and b in a,
    'starts_with': lambda a, b: isinstance(a, str) and a.startswith(str(b)),
    'ends_with':   lambda a, b: isinstance(a, str) and a.endswith(str(b)),
}


class PolicyEngine:
    """
    Deterministic rules engine.
    Input:  action_type, payload dict, list of PolicyRule objects
    Output: PolicyResult with APPROVE / BLOCK / ESCALATE

    Design: rules are evaluated in order. First rule whose conditions
    match the payload is the decision. Remaining rules are skipped.

    Each rule supports:
      - conditions (ALL must match -- AND logic)
      - any_of (at least one must match -- OR logic)

    If no rule matches: BLOCK with reason_code NO_POLICY_MATCHED.
    This is fail-closed: unknown action + no match = BLOCK.
    """

    def evaluate(
        self,
        action_type: str,
        payload:     Dict[str, Any],
        rules:       List[PolicyRule],
    ) -> PolicyResult:
        evaluated_rule_ids: List[str] = []

        for rule in rules:
            if rule.action_type != action_type:
                continue

            evaluated_rule_ids.append(rule.rule_id)

            # AND logic: all conditions in `conditions` must match
            and_match = self._all_conditions_match(rule.conditions, payload)

            # OR logic: at least one condition in `any_of` must match (if present)
            any_of = getattr(rule, 'any_of', None)
            if any_of:
                or_match = any(
                    self._single_condition_matches(cond, payload)
                    for cond in any_of
                )
            else:
                or_match = True  # No OR clause = passes by default

            if and_match and or_match:
                return PolicyResult(
                    status=rule.action,
                    rule_triggered=rule.rule_id,
                    rules_evaluated=evaluated_rule_ids,
                    reason=rule.reason,
                    reason_code=rule.reason_code,
                    policy_version=rule.version,
                    escalation=rule.escalation_config,
                )

        # No rule matched: BLOCK (fail-closed)
        return PolicyResult(
            status='BLOCK',
            rule_triggered=None,
            rules_evaluated=evaluated_rule_ids,
            reason='No matching policy rule found -- blocked by default (fail-closed)',
            reason_code='NO_POLICY_MATCHED',
            policy_version='default',
        )

    def _single_condition_matches(
        self,
        cond: PolicyCondition,
        payload: Dict[str, Any],
    ) -> bool:
        payload_value = payload.get(cond.field)
        if payload_value is None:
            return False
        op_fn = OPS.get(cond.operator)
        if op_fn is None:
            return False
        try:
            return bool(op_fn(payload_value, cond.value))
        except (TypeError, ValueError):
            return False

    def _all_conditions_match(
        self,
        conditions: List[PolicyCondition],
        payload:    Dict[str, Any],
    ) -> bool:
        for cond in conditions:
            if not self._single_condition_matches(cond, payload):
                return False
        return True


policy_engine = PolicyEngine()
