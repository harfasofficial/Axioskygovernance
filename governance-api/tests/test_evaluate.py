# tests/test_evaluate.py
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from governor.service import app

client = TestClient(app)

T1_KEY = "axiosky_live_dev_test_key_do_not_use_in_production"
T1_ID  = "1"
T1_HDR = {"Authorization": f"Bearer {T1_KEY}"}
T1_MOCK = {"tenant_id": T1_ID, "org_name": "Test Fintech", "plan_tier": "pilot"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eval_body(action_type="loan_approval", amount=500000, environment="shadow"):
    """Return a minimal valid evaluate request body."""
    return {
        "agent_id": "loan-agent",
        "action_type": action_type,
        "timestamp": "2026-06-19T10:00:00Z",
        "environment": environment,
        "payload": {"amount": amount},
    }


# ---------------------------------------------------------------------------
# Core evaluate
# ---------------------------------------------------------------------------

def test_evaluate_shadow_mode_returns_approve():
    """In shadow mode the API always returns APPROVE but logs the real decision."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json=_eval_body())
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "APPROVE"
        assert data["decision_id"] is not None
        assert "latency_ms" in data


def test_shadow_result_fields_present():
    """shadow_result and shadow_would_escalate must be present in shadow-mode responses."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json=_eval_body())
        assert r.status_code == 200
        data = r.json()
        assert "shadow_result" in data
        assert "shadow_would_escalate" in data


def test_receipt_signature_present():
    """Every decision response must carry a receipt_signature and payload_hash."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json=_eval_body())
        assert r.status_code == 200
        data = r.json()
        assert "receipt_signature" in data and data["receipt_signature"]
        assert "payload_hash" in data and data["payload_hash"]


def test_evaluate_high_amount_production_blocked():
    """Loans above Rs 50L should be blocked in production."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR,
                        json=_eval_body(amount=60_000_000, environment="production"))
        assert r.status_code == 200
        # Amount > 50L: BLOCK per rbi_high_value_loan_block rule
        assert r.json()["status"] in ("BLOCK", "ESCALATE")


def test_evaluate_low_amount_production_approved():
    """Small loans within policy limits should be approved in production."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR,
                        json=_eval_body(amount=100_000, environment="production"))
        assert r.status_code == 200
        assert r.json()["status"] == "APPROVE"


def test_evaluate_unauthorized_no_header():
    """Missing Authorization header must return 401."""
    r = client.post("/v1/evaluate", json=_eval_body())
    assert r.status_code == 401


def test_decision_id_in_response_header():
    """X-Decision-ID header must match decision_id in the JSON body."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json=_eval_body())
        assert r.status_code == 200
        assert "x-decision-id" in r.headers
        assert r.headers["x-decision-id"] == r.json()["decision_id"]


def test_evaluate_with_idempotency_key():
    """Same idempotency key should return 200 both times (cached or fresh)."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Idempotency-Key": "idem-test-abc-123"}
        r1 = client.post("/v1/evaluate", headers=headers, json=_eval_body())
        assert r1.status_code == 200
        r2 = client.post("/v1/evaluate", headers=headers, json=_eval_body())
        assert r2.status_code == 200


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------

def test_fail_closed_unknown_action_type():
    """
    An action_type with no policy rules must be BLOCKED (fail-closed).
    This is the most critical security property of the policy engine.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR,
                        json=_eval_body(action_type="totally_unknown_action_xyz",
                                        environment="production"))
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "BLOCK"
        assert data["reason_code"] == "NO_POLICY_DEFINED"


def test_fail_closed_unknown_action_shadow_returns_approve_but_logs_block():
    """
    In shadow mode, response is APPROVE but shadow_result should be BLOCK.
    """
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR,
                        json=_eval_body(action_type="totally_unknown_action_xyz",
                                        environment="shadow"))
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "APPROVE"          # shadow always returns APPROVE
        assert data["shadow_result"] == "BLOCK"      # but shadow_result is the real decision


# ---------------------------------------------------------------------------
# Batch evaluate
# ---------------------------------------------------------------------------

def test_batch_evaluate_returns_results_for_each_action():
    """Batch endpoint must return one result per input action."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate/batch", headers=T1_HDR, json={
            "actions": [
                _eval_body(amount=100_000, environment="shadow"),
                _eval_body(amount=200_000, environment="shadow"),
            ]
        })
        assert r.status_code == 200
        data = r.json()
        assert data["batch_size"] == 2
        assert data["processed"] == 2
        assert len(data["results"]) == 2
        for result in data["results"]:
            assert result["success"] is True
            assert "decision" in result


def test_batch_evaluate_empty_list_rejected():
    """Batch with 0 actions must be rejected with 422."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate/batch", headers=T1_HDR, json={"actions": []})
        assert r.status_code == 422


def test_batch_evaluate_above_100_actions_rejected():
    """Batch with >100 actions must be rejected with 422."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        actions = [_eval_body() for _ in range(101)]
        r = client.post("/v1/evaluate/batch", headers=T1_HDR, json={"actions": actions})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Policy simulate
# ---------------------------------------------------------------------------

def test_policy_simulate_known_action_type():
    """Simulate must return a result without writing to the audit log."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/policies/simulate", headers=T1_HDR, json={
            "action_type": "loan_approval",
            "payload": {"amount": 100_000},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["simulated"] is True
        assert "result" in data
        assert data["result"]["status"] in ("APPROVE", "BLOCK", "ESCALATE")


def test_policy_simulate_unknown_action_type_returns_block():
    """Simulate on unknown action_type must return BLOCK with NO_POLICY_DEFINED."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/policies/simulate", headers=T1_HDR, json={
            "action_type": "nonexistent_action_type_xyz",
            "payload": {"foo": "bar"},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["result"]["status"] == "BLOCK"
        assert data["result"]["reason_code"] == "NO_POLICY_DEFINED"
        assert "warning" in data


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------

def test_payload_too_large_rejected():
    """Payloads over 64KB must be rejected with 422."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        # Build a payload slightly over 65536 bytes
        large_payload = {"data": "x" * 70_000}
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-06-19T10:00:00Z",
            "environment": "shadow",
            "payload": large_payload,
        })
        assert r.status_code == 422


def test_invalid_environment_rejected():
    """environment field must be 'shadow' or 'production' only."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-06-19T10:00:00Z",
            "environment": "staging",  # invalid
            "payload": {"amount": 1000},
        })
        assert r.status_code == 422
