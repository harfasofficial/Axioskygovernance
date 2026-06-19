import pytest
import uuid
import hashlib
import json
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from governor.service import app
from database.session import AsyncSessionLocal
from database.models import AuditLog, Escalation

client = TestClient(app)

T1_KEY = "axiosky_live_dev_test_key_do_not_use_in_production"
T1_ID = "1"
T1_HDR = {"Authorization": f"Bearer {T1_KEY}"}

T2_KEY = "axiosky_live_tenant2_test_key_do_not_use_in_production"
T2_ID = "2"
T2_HDR = {"Authorization": f"Bearer {T2_KEY}"}

T1_MOCK = {"tenant_id": T1_ID, "org_name": "Test Fintech",  "plan_tier": "pilot"}
T2_MOCK = {"tenant_id": T2_ID, "org_name": "Rival Fintech", "plan_tier": "pilot"}


async def write_t2_audit_entry() -> str:
    d_id = str(uuid.uuid4())
    ph = hashlib.sha256(json.dumps({"amount": 1}).encode()).hexdigest()
    dh = hashlib.sha256(f"{ph}:BLOCK".encode()).hexdigest()
    async with AsyncSessionLocal() as db:
        db.add(AuditLog(
            decision_id=d_id, tenant_id=T2_ID, agent_id="t2_agent",
            action_type="loan_approval", status="BLOCK", environment="shadow",
            reason="T2 test", reason_code="T2_TEST", rule_triggered=None,
            policy_version="v1", latency_ms=5, payload_hash=ph, decision_hash=dh,
        ))
        await db.commit()
    return d_id


async def write_t2_escalation() -> str:
    from datetime import datetime, timedelta, timezone
    esc_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as db:
        db.add(Escalation(
            escalation_id=esc_id, tenant_id=T2_ID,
            decision_id=str(uuid.uuid4()), agent_id="t2_agent",
            action_type="loan_approval", reason="T2 escalation",
            reason_code="T2_ESC", status="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        await db.commit()
    return esc_id


def test_cannot_read_other_tenant_audit_logs():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.get("/v1/audit-logs", headers=T1_HDR)
        assert r.status_code == 200
        entries = r.json()["entries"]
        t2_entries = [e for e in entries if e["agent_id"] == "t2_agent"]
        assert len(t2_entries) == 0, f"LEAK: T1 can see {len(t2_entries)} T2 audit entries"


def test_cannot_verify_other_tenant_chain():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/audit-logs/verify", headers=T1_HDR, json={"tenant_id": T2_ID})
        assert r.status_code == 403, f"LEAK: T1 can verify T2 chain, got {r.status_code}"


def test_cannot_read_other_tenant_shadow_report():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.get("/v1/reports/shadow", headers=T1_HDR)
        assert r.status_code == 200
        data = r.json()
        assert data["tenant_id"] == T1_ID, f"LEAK: report tenant_id is {data['tenant_id']}"


def test_cannot_list_other_tenant_escalations():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.get("/v1/escalations", headers=T1_HDR)
        assert r.status_code == 200
        escs = r.json()["escalations"]
        t2_escs = [e for e in escs if e.get("agent_id") == "t2_agent"]
        assert len(t2_escs) == 0, f"LEAK: T1 can see {len(t2_escs)} T2 escalations"


@pytest.mark.asyncio
async def test_cannot_approve_other_tenant_escalation():
    esc_id = await write_t2_escalation()
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post(
            f"/v1/escalations/{esc_id}/approve",
            headers=T1_HDR,
            json={"resolved_by": "compliance@t1.com"}
        )
        assert r.status_code == 400, f"LEAK: T1 approved T2 escalation, got {r.status_code}"


@pytest.mark.asyncio
async def test_cannot_reject_other_tenant_escalation():
    esc_id = await write_t2_escalation()
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post(
            f"/v1/escalations/{esc_id}/reject",
            headers=T1_HDR,
            json={"resolved_by": "compliance@t1.com"}
        )
        assert r.status_code == 400, f"LEAK: T1 rejected T2 escalation, got {r.status_code}"


def test_payload_tenant_id_mismatch_returns_403():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T1_MOCK):
        r = client.post("/v1/evaluate", headers=T1_HDR, json={
            "agent_id": "attacker", "action_type": "loan_approval",
            "timestamp": "2026-04-04T10:00:00Z",
            "tenant_id": T2_ID,
            "environment": "production", "payload": {"amount": 1000}
        })
        assert r.status_code == 403, f"LEAK: tenant_id injection succeeded, got {r.status_code}"


def test_no_api_key_returns_401():
    r = client.post("/v1/evaluate", json={
        "agent_id": "anon", "action_type": "loan_approval",
        "timestamp": "2026-04-04T10:00:00Z",
        "tenant_id": T1_ID, "environment": "production", "payload": {"amount": 1000}
    })
    assert r.status_code == 401


def test_wrong_api_key_returns_401():
    r = client.post("/v1/evaluate",
                    headers={"Authorization": "Bearer totally_fake_key"},
                    json={
                        "agent_id": "anon", "action_type": "loan_approval",
                        "timestamp": "2026-04-04T10:00:00Z",
                        "tenant_id": T1_ID, "environment": "production",
                        "payload": {"amount": 1000}
                    })
    assert r.status_code == 401


def test_t2_key_cannot_read_t1_audit_logs():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T2_MOCK):
        r = client.get("/v1/audit-logs", headers=T2_HDR)
        assert r.status_code == 200
        entries = r.json()["entries"]
        t1_entries = [e for e in entries if e.get("agent_id") == "loan-agent"]
        assert len(t1_entries) == 0, f"LEAK: T2 can see {len(t1_entries)} T1 audit entries"


def test_t2_key_cannot_read_t1_escalations():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T2_MOCK):
        r = client.get("/v1/escalations", headers=T2_HDR)
        assert r.status_code == 200
        escs = r.json()["escalations"]
        t1_escs = [e for e in escs if e.get("agent_id") == "loan-agent"]
        assert len(t1_escs) == 0, f"LEAK: T2 can see {len(t1_escs)} T1 escalations"


def test_t2_key_cannot_verify_t1_chain():
    with patch("auth.service.AuthService.validate", new_callable=AsyncMock, return_value=T2_MOCK):
        r = client.post("/v1/audit-logs/verify", headers=T2_HDR, json={"tenant_id": T1_ID})
        assert r.status_code == 403, f"LEAK: T2 can verify T1 chain, got {r.status_code}"


def test_health_endpoint_responds_fast():
    import time
    start = time.time()
    r = client.get("/health")
    elapsed_ms = (time.time() - start) * 1000
    assert r.status_code == 200
    assert elapsed_ms < 2000, f"Health endpoint too slow: {elapsed_ms:.1f}ms"
