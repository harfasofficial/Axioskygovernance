import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from database.models import Escalation
from database.session import AsyncSessionLocal
from escalations.service import EscalationService
from policy_engine.models import EscalationConfig

svc = EscalationService()


def make_config(expires_minutes=60, action_on_expiry="BLOCK"):
    return EscalationConfig(
        target_role="cro",
        expires_minutes=expires_minutes,
        action_on_expiry=action_on_expiry,
    )


@pytest.mark.asyncio
async def test_create_saves_escalation_record():
    escalation_id = await svc.create(
        tenant_id="t1",
        decision_id=str(uuid.uuid4()),
        agent_id="ag",
        action_type="loan_approval",
        reason="Test",
        reason_code="TEST_001",
        rule_triggered="rbi_high_value_escalate",
        config=make_config(),
        webhook_url=None,
    )

    assert escalation_id is not None

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Escalation).where(Escalation.escalation_id == escalation_id)
        )
        esc = result.scalar_one_or_none()

    assert esc is not None
    assert esc.status == "pending"
    assert esc.resolved_at is None


@pytest.mark.asyncio
async def test_create_fires_webhook_when_url_provided():
    with patch.object(svc, "_fire_webhook_with_retry", new_callable=AsyncMock) as mock_fire:
        await svc.create(
            tenant_id="t1",
            decision_id=str(uuid.uuid4()),
            agent_id="ag",
            action_type="loan_approval",
            reason="Test",
            reason_code="TEST",
            rule_triggered="rule1",
            config=make_config(),
            webhook_url="https://customer.internal/webhook",
        )
        await asyncio.sleep(0.01)

    mock_fire.assert_called_once()


@pytest.mark.asyncio
async def test_create_skips_webhook_when_no_url():
    with patch.object(svc, "_fire_webhook_with_retry", new_callable=AsyncMock) as mock_fire:
        await svc.create(
            tenant_id="t1",
            decision_id=str(uuid.uuid4()),
            agent_id="ag",
            action_type="loan_approval",
            reason="Test",
            reason_code="TEST",
            rule_triggered="rule1",
            config=make_config(),
            webhook_url=None,
        )
        await asyncio.sleep(0.01)

    mock_fire.assert_not_called()


@pytest.mark.asyncio
async def test_resolve_approves_pending_escalation():
    escalation_id = await svc.create(
        tenant_id="t1",
        decision_id=str(uuid.uuid4()),
        agent_id="ag",
        action_type="loan_approval",
        reason="Test",
        reason_code="TEST",
        rule_triggered="rule1",
        config=make_config(),
        webhook_url=None,
    )

    result = await svc.resolve(
        escalation_id=escalation_id,
        tenant_id="t1",
        human_decision="approved",
        resolved_by="cro@bank.com",
    )

    assert "error" not in result
    assert result["status"] == "approved"
    assert result["resolved_by"] == "cro@bank.com"


@pytest.mark.asyncio
async def test_resolve_fails_for_nonexistent_escalation():
    result = await svc.resolve(
        escalation_id=str(uuid.uuid4()),
        tenant_id="t1",
        human_decision="approved",
        resolved_by="cro@bank.com",
    )

    assert "error" in result


@pytest.mark.asyncio
async def test_webhook_signature_generation():
    payload = {"event": "test", "data": "value"}
    secret = "test_secret"
    sig = EscalationService._sign_payload(payload, secret)

    assert len(sig) == 64  # SHA-256 hex
    assert isinstance(sig, str)


@pytest.mark.asyncio
async def test_webhook_url_validation_blocks_internal():
    assert EscalationService._is_valid_webhook_url("http://localhost/hook") is False
    assert EscalationService._is_valid_webhook_url("http://127.0.0.1/hook") is False
    assert EscalationService._is_valid_webhook_url("https://example.com/hook") is True
