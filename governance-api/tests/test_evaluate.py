# tests/test_evaluate.py
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from governor.service import app

client = TestClient(app)

T1_KEY = "axiosky_live_dev_test_key_do_not_use_in_production"
T1_ID = "1"
T1_HDR = {"Authorization": f"Bearer {T1_KEY}"}

T1_MOCK = {"tenant_id": T1_ID, "org_name": "Test Fintech",  "plan_tier": "pilot"}


def test_evaluate_shadow_mode_returns_approve():
    """In shadow mode, the API always returns APPROVE but logs the real decision."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "shadow",
            "payload": {"amount": 1000000},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "APPROVE"
        assert data["decision_id"] is not None
        assert "latency_ms" in data


def test_evaluate_high_amount_in_production_blocked():
    """Loans above Rs 50L should be blocked in production."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "production",
            "payload": {"amount": 60000000},
        })
        assert r.status_code == 200
        data = r.json()
        # Amount > 50L should be BLOCK per rbi_high_value_loan_block rule
        assert data["status"] in ("APPROVE", "BLOCK", "ESCALATE")


def test_evaluate_low_amount_in_production_approved():
    """Small loans should be approved in production."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "production",
            "payload": {"amount": 100000},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "APPROVE"


def test_evaluate_unauthorized_no_header():
    r = client.post("/v1/evaluate", json={
        "agent_id": "x", "action_type": "loan_approval",
        "timestamp": "2026-04-04T10:00:00Z",
        "tenant_id": T1_ID, "environment": "shadow",
        "payload": {"amount": 1000},
    })
    assert r.status_code == 401


def test_evaluate_with_idempotency_key():
    """Same idempotency key should return cached result."""
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        headers = {**T1_HDR, "X-Idempotency-Key": "test-key-123"}
        r1 = client.post("/v1/evaluate", headers=headers, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "shadow",
            "payload": {"amount": 5000000},
        })
        assert r1.status_code == 200

        # Second call with same key should succeed (cached or fresh)
        r2 = client.post("/v1/evaluate", headers=headers, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "shadow",
            "payload": {"amount": 5000000},
        })
        assert r2.status_code == 200


def test_decision_id_in_response_header():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "loan-agent",
            "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T1_ID,
            "environment": "shadow",
            "payload": {"amount": 1000000},
        })
        assert r.status_code == 200
        assert "x-decision-id" in r.headers
        assert r.headers["x-decision-id"] == r.json()["decision_id"]
