# escalations/service.py
import asyncio
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from sqlalchemy import select

from database.models import Escalation
from database.session import AsyncSessionLocal
from policy_engine.models import EscalationConfig
from security.ssrf import validate_url_and_resolve

logger = logging.getLogger(__name__)

# Must be set explicitly in every deployed environment.
PUBLIC_BASE_URL = os.getenv("AXIOSKY_PUBLIC_BASE_URL", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")


class EscalationService:
    """
    Manages the human-in-the-loop workflow for ESCALATE decisions.
    All outgoing webhooks are signed with HMAC-SHA256 for authenticity.
    SSRF protection for webhook URLs is handled by security.ssrf module.
    """

    @staticmethod
    def _is_valid_webhook_url(url: str) -> bool:
        try:
            validate_url_and_resolve(url)
            return True
        except ValueError as e:
            logger.warning("Webhook URL rejected (SSRF): %s", e)
            return False

    @staticmethod
    def _sign_payload(payload: dict, secret: str) -> str:
        if not secret:
            raise ValueError("WEBHOOK_SECRET must be set before signing payloads")
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    async def create(
        self,
        tenant_id: int,
        decision_id: str,
        agent_id: str,
        action_type: str,
        reason: str,
        reason_code: str,
        rule_triggered: Optional[str],
        config: EscalationConfig,
        webhook_url: Optional[str],
        action_on_expiry: str = "BLOCK",
    ) -> str:
        escalation_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=config.expires_minutes
        )

        async with AsyncSessionLocal() as db:
            esc = Escalation(
                escalation_id=escalation_id,
                tenant_id=tenant_id,
                decision_id=decision_id,
                agent_id=agent_id,
                action_type=action_type,
                reason=reason,
                reason_code=reason_code,
                rule_triggered=rule_triggered,
                status="pending",
                webhook_url=webhook_url,
                expires_at=expires_at,
                action_on_expiry=action_on_expiry,
            )
            db.add(esc)
            await db.commit()

        if webhook_url:
            if not self._is_valid_webhook_url(webhook_url):
                logger.warning("Invalid webhook URL rejected: %s", webhook_url)
            else:
                asyncio.create_task(
                    self._fire_webhook_with_retry(
                        webhook_url=webhook_url,
                        escalation_id=escalation_id,
                        decision_id=decision_id,
                        agent_id=agent_id,
                        action_type=action_type,
                        reason=reason,
                        reason_code=reason_code,
                        rule_triggered=rule_triggered,
                        expires_at=expires_at.isoformat(),
                        action_on_expiry=action_on_expiry,
                        expires_minutes=config.expires_minutes,
                        target_role=config.target_role,
                    )
                )

        return escalation_id

    async def _fire_webhook_with_retry(self, webhook_url: str, escalation_id: str, **context) -> None:
        if not PUBLIC_BASE_URL:
            logger.warning(
                "AXIOSKY_PUBLIC_BASE_URL is not set -- skipping approval/reject URL generation "
                "for escalation %s. Set this env var in every deployed environment.",
                escalation_id,
            )
            return

        payload = {
            "event": "escalation_created",
            "escalation_id": escalation_id,
            "approve_url": f"{PUBLIC_BASE_URL}/v1/escalations/{escalation_id}/approve",
            "reject_url": f"{PUBLIC_BASE_URL}/v1/escalations/{escalation_id}/reject",
            "context": context,
        }

        headers = {"Content-Type": "application/json"}

        if WEBHOOK_SECRET:
            signature = self._sign_payload(payload, WEBHOOK_SECRET)
            headers["X-Axiosky-Signature"] = f"sha256={signature}"
        else:
            logger.warning(
                "WEBHOOK_SECRET not set -- webhook for escalation %s will be unsigned",
                escalation_id,
            )

        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(webhook_url, json=payload, headers=headers)

                logger.info(
                    "Escalation webhook %s - HTTP %s (attempt %d)",
                    escalation_id, response.status_code, attempt + 1,
                )

                if response.status_code < 500:
                    return

            except Exception as exc:
                logger.error(
                    "Escalation webhook failed for %s (attempt %d): %s",
                    escalation_id, attempt + 1, exc,
                )

            await asyncio.sleep(2 ** attempt)

        logger.error(
            "Escalation webhook for %s failed after 3 attempts -- delivery abandoned",
            escalation_id,
        )

    async def resolve(
        self,
        escalation_id: str,
        tenant_id: int,
        human_decision: str,
        resolved_by: str,
    ) -> dict:
        async with AsyncSessionLocal() as db:
            stmt = select(Escalation).where(
                Escalation.escalation_id == escalation_id,
                Escalation.tenant_id == tenant_id,
            )
            result = await db.execute(stmt)
            esc = result.scalar_one_or_none()

            if not esc:
                return {"error": "Escalation not found or wrong tenant"}

            if esc.status != "pending":
                return {"error": f"Escalation already resolved: {esc.status}"}

            now = datetime.now(timezone.utc)
            esc_expires_at = (
                esc.expires_at.replace(tzinfo=timezone.utc)
                if esc.expires_at.tzinfo is None
                else esc.expires_at
            )

            if now > esc_expires_at:
                esc.status = "expired"
                esc.resolved_at = now
                esc.resolved_by = "system_expiry"
                await db.commit()
                return {"error": "Escalation has expired"}

            esc.status = human_decision
            esc.resolved_at = now
            esc.resolved_by = resolved_by
            await db.commit()

            return {
                "escalation_id": escalation_id,
                "status": human_decision,
                "resolved_by": resolved_by,
                "resolved_at": esc.resolved_at.isoformat() if esc.resolved_at else None,
            }


escalation_service = EscalationService()
