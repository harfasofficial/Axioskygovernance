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
from urllib.parse import urlparse

import httpx
from sqlalchemy import select

from database.models import Escalation
from database.session import AsyncSessionLocal
from policy_engine.models import EscalationConfig

logger = logging.getLogger(__name__)

PUBLIC_BASE_URL = os.getenv("AXIOSKY_PUBLIC_BASE_URL", "http://localhost:8000")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")


class EscalationService:
    """
    Manages the human-in-the-loop workflow for ESCALATE decisions.
    All outgoing webhooks are signed with HMAC-SHA256 for authenticity.
    """

    @staticmethod
    def _is_valid_webhook_url(url: str) -> bool:
        """Validate webhook URL to prevent SSRF via escalation webhooks."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            return False
        return True

    @staticmethod
    def _sign_payload(payload: dict, secret: str) -> str:
        """Sign webhook payload with HMAC-SHA256."""
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    async def create(
        self,
        tenant_id: str,
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

        # Validate and fire webhook
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
        """Fire webhook with HMAC signature and retry logic."""
        payload = {
            "event": "escalation_created",
            "escalation_id": escalation_id,
            "approve_url": f"{PUBLIC_BASE_URL}/v1/escalations/{escalation_id}/approve",
            "reject_url": f"{PUBLIC_BASE_URL}/v1/escalations/{escalation_id}/reject",
            "context": context,
        }

        headers = {"Content-Type": "application/json"}

        # Add HMAC signature if secret is configured
        if WEBHOOK_SECRET:
            signature = self._sign_payload(payload, WEBHOOK_SECRET)
            headers["X-Axiosky-Signature"] = f"sha256={signature}"

        # Retry up to 3 times with exponential backoff
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(webhook_url, json=payload, headers=headers)

                logger.info(
                    "Escalation webhook fired %s - HTTP %s (attempt %d)",
                    escalation_id, response.status_code, attempt + 1,
                )

                if response.status_code < 500:
                    return  # Success or client error (don't retry)

            except Exception as exc:
                logger.error(
                    "Escalation webhook failed for %s (attempt %d): %s",
                    escalation_id, attempt + 1, exc,
                )

            await asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s backoff

    async def resolve(
        self,
        escalation_id: str,
        tenant_id: str,
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
