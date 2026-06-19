# audit/service.py
import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from audit.models import AuditEntry
from database.models import AuditLog
from database.session import AsyncSessionLocal

logger = logging.getLogger(__name__)

_chain_locks: dict[int, asyncio.Lock] = {}


class AuditService:
    """
    Handles all audit logging for governance decisions.

    Design principles:
    1. Audit writes can run async for latency-sensitive flows (best-effort), or
       synchronously via write_durable() for crash-proof durability.
    2. The fire-and-forget wrapper never raises to the caller.
    3. Every entry is chained to the previous via SHA-256 hash.
    4. The chain can be verified by any external party at any time.
    5. Per-tenant locking prevents race conditions on concurrent writes.
    """

    @staticmethod
    def _sha256(data) -> str:
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(str(data).encode('utf-8')).hexdigest()

    @staticmethod
    def compute_payload_hash(payload: dict) -> str:
        return AuditService._sha256(payload)

    @staticmethod
    def compute_decision_hash(payload_hash: str, status: str) -> str:
        return AuditService._sha256(f'{payload_hash}:{status}')

    async def _get_last_hash(
        self, tenant_id: int, db: AsyncSession
    ) -> Optional[str]:
        stmt = (
            select(AuditLog.decision_hash)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.id.desc())
            .limit(1)
            .with_for_update()
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def _write_entry(self, entry: AuditEntry, payload: dict):
        lock = _chain_locks.setdefault(entry.tenant_id, asyncio.Lock())

        async with lock:
            async with AsyncSessionLocal() as db:
                async with db.begin():
                    payload_hash = self.compute_payload_hash(payload)
                    previous_hash = await self._get_last_hash(entry.tenant_id, db)
                    decision_hash = self.compute_decision_hash(payload_hash, entry.status)

                    log_row = AuditLog(
                        decision_id=entry.decision_id,
                        tenant_id=entry.tenant_id,
                        agent_id=entry.agent_id,
                        action_type=entry.action_type,
                        status=entry.status,
                        environment=entry.environment,
                        reason=entry.reason,
                        reason_code=entry.reason_code,
                        rule_triggered=entry.rule_triggered,
                        policy_version=entry.policy_version,
                        latency_ms=entry.latency_ms,
                        payload_hash=payload_hash,
                        decision_hash=decision_hash,
                        previous_hash=previous_hash,
                        created_at=datetime.now(timezone.utc),
                    )
                    db.add(log_row)

                logger.debug("Audit logged: %s %s", entry.decision_id, entry.status)

    async def write_durable(self, entry: AuditEntry, payload: dict) -> None:
        """Synchronous awaited write -- stronger durability guarantee."""
        await self._write_entry(entry, payload)

    async def log(self, entry: AuditEntry, payload: dict) -> None:
        """Best-effort wrapper for background task scheduling. Swallows exceptions."""
        try:
            await self._write_entry(entry, payload)
        except Exception as e:
            logger.error(
                "Audit log write failed for decision_id=%s: %s",
                entry.decision_id, e, exc_info=True
            )

    async def verify_chain(
        self,
        tenant_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> dict:
        """Verify the hash chain in chunks to avoid memory issues."""
        CHUNK_SIZE = 5000
        total_checked = 0
        previous_chain_hash = None
        offset = 0

        async with AsyncSessionLocal() as db:
            while True:
                stmt = (
                    select(AuditLog)
                    .where(AuditLog.tenant_id == tenant_id)
                    .order_by(AuditLog.id.asc())
                    .limit(CHUNK_SIZE)
                    .offset(offset)
                )

                if start_date:
                    stmt = stmt.where(AuditLog.created_at >= start_date)
                if end_date:
                    stmt = stmt.where(AuditLog.created_at <= end_date)

                result = await db.execute(stmt)
                entries = result.scalars().all()

                if not entries:
                    break

                for i, entry in enumerate(entries):
                    global_idx = offset + i
                    if global_idx == 0:
                        if entry.previous_hash is not None:
                            return {
                                'chain_intact': False,
                                'broken_at_id': entry.id,
                                'broken_at_time': entry.created_at.isoformat(),
                                'detail': 'First audit entry must have previous_hash = null.',
                            }
                    elif entry.previous_hash != previous_chain_hash:
                        return {
                            'chain_intact': False,
                            'broken_at_id': entry.id,
                            'broken_at_time': entry.created_at.isoformat(),
                            'detail': (
                                f'Entry {entry.id} previous_hash does not match '
                                f'expected chain hash. Possible tampering or '
                                f'concurrent write issue.'
                            ),
                        }
                    previous_chain_hash = entry.decision_hash

                total_checked += len(entries)
                offset += CHUNK_SIZE

        if total_checked == 0:
            return {
                'chain_intact': True,
                'entries_checked': 0,
                'message': 'No entries in range',
            }

        return {
            'chain_intact': True,
            'entries_checked': total_checked,
            'verified_at': datetime.now(timezone.utc).isoformat(),
        }


audit_service = AuditService()
