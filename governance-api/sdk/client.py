# sdk/client.py
"""
Axiosky Python SDK -- Client for the Governance API.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx


@dataclass
class DecisionResult:
    """Result of an evaluate() call."""
    decision_id: str
    status: str             # APPROVE | BLOCK | ESCALATE (or APPROVE in shadow with shadow_result set)
    reason: str
    reason_code: str
    latency_ms: int
    shadow_result: Optional[str] = None
    shadow_result_reason: Optional[str] = None
    escalation_id: Optional[str] = None
    rule_triggered: Optional[str] = None
    policy_version: Optional[str] = None

    @property
    def is_approved(self) -> bool:
        return self.status == "APPROVE"

    @property
    def is_blocked(self) -> bool:
        return self.status == "BLOCK"

    @property
    def is_escalated(self) -> bool:
        return self.status == "ESCALATE"


class AxioskyError(Exception):
    """Error from the Axiosky API."""
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code


class AxioskyClient:
    """
    Axiosky AI Governance SDK.

    Usage:
        from sdk import AxioskyClient

        client = AxioskyClient(
            api_key="axiosky_live_your_key_here",
            tenant_id="1",
            base_url="https://api.axiosky.com",
            environment="shadow",  # start with shadow mode
        )

        result = client.evaluate(
            agent_id="loan_agent_v1",
            action_type="loan_approval",
            payload={"amount": 5000000, "customer_id": "CUST_001"},
        )

        if result.is_blocked:
            raise Exception(f"Action blocked: {result.reason}")
    """

    def __init__(
        self,
        api_key: str,
        tenant_id: str,
        base_url: str = "https://api.axiosky.com",
        environment: str = "shadow",
        timeout: float = 10.0,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")

        self.tenant_id = tenant_id
        self.environment = environment
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"axiosky-python-sdk/0.2.0",
        }
        self._timeout = timeout

    def evaluate(
        self,
        agent_id: str,
        action_type: str,
        payload: Dict[str, Any],
        context_hooks: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> DecisionResult:
        """
        Evaluate an AI agent action against governance policies.

        Args:
            agent_id: Identifier for the AI agent making the decision.
            action_type: Type of action (e.g. "loan_approval", "access_customer_data").
            payload: The action parameters to evaluate.
            context_hooks: Optional dict of hook_name -> URL for live context enrichment.
            metadata: Optional metadata (e.g. escalation_webhook URL).
            idempotency_key: Optional key to prevent duplicate evaluations.

        Returns:
            DecisionResult with status APPROVE, BLOCK, or ESCALATE.

        Raises:
            AxioskyError: If the API returns an error or is unreachable.
        """
        body = {
            "agent_id": agent_id,
            "action_type": action_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "payload": payload,
        }
        if context_hooks:
            body["context_hooks"] = context_hooks
        if metadata:
            body["metadata"] = metadata

        headers = dict(self._headers)
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/v1/evaluate",
                    json=body,
                    headers=headers,
                )
        except httpx.TimeoutException:
            raise AxioskyError(f"Axiosky API timed out after {self._timeout}s")
        except httpx.RequestError as e:
            raise AxioskyError(f"Axiosky API unreachable: {e}")

        if response.status_code == 401:
            raise AxioskyError("Invalid or expired API key", status_code=401)
        if response.status_code == 429:
            raise AxioskyError("Rate limit exceeded. Retry after 60s.", status_code=429)
        if not response.is_success:
            raise AxioskyError(
                f"Axiosky API error {response.status_code}: {response.text}",
                status_code=response.status_code,
            )

        data = response.json()
        return DecisionResult(
            decision_id=data["decision_id"],
            status=data["status"],
            reason=data["reason"],
            reason_code=data["reason_code"],
            latency_ms=data["latency_ms"],
            shadow_result=data.get("shadow_result"),
            shadow_result_reason=data.get("shadow_result_reason"),
            escalation_id=data.get("escalation_id"),
            rule_triggered=data.get("rule_triggered"),
            policy_version=data.get("policy_version"),
        )

    def health(self) -> dict:
        """Check if the Axiosky API is reachable."""
        try:
            with httpx.Client(timeout=5.0) as client:
                return client.get(f"{self._base_url}/health").json()
        except httpx.RequestError as e:
            raise AxioskyError(f"Axiosky API unreachable: {e}")

    def close(self):
        """Close the client (no-op for sync client, for API compatibility)."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
