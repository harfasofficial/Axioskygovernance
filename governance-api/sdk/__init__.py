"""
Axiosky Python SDK

Usage:
    from sdk import AxioskyClient

    client = AxioskyClient(
        api_key="axiosky_live_your_key_here",
        tenant_id="1",
        base_url="https://api.axiosky.com",
    )

    result = client.evaluate(
        agent_id="loan_agent_v1",
        action_type="loan_approval",
        payload={"amount": 5000000, "customer_id": "CUST_001"},
    )

    print(result.status)  # APPROVE | BLOCK | ESCALATE
"""
from sdk.client import AxioskyClient, DecisionResult, AxioskyError

__version__ = "0.2.0"
__all__ = ["AxioskyClient", "DecisionResult", "AxioskyError"]
