# database/base_repo.py
"""
TenantScopedRepo -- Layer 2 tenant isolation.
Most tenant-scoped read access goes through this repository.
Every query here is structurally scoped to a tenant_id.

Note: a few specialized services (for example audit chain writes and
escalation workflow writes) still open direct sessions for transactional
or background-task reasons. Keep this docstring aligned with reality.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AuditLog, Escalation


class TenantScopedRepo:
    def __init__(self, tenant_id: int, db: AsyncSession):
        self.tenant_id = tenant_id
        self.db = db

    async def get_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        status_filter: str = None,
        agent_id: str = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> list:
        stmt = (
            select(AuditLog)
            .where(AuditLog.tenant_id == self.tenant_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status_filter:
            stmt = stmt.where(AuditLog.status == status_filter)
        if agent_id:
            stmt = stmt.where(AuditLog.agent_id == agent_id)
        if start_date:
            stmt = stmt.where(AuditLog.created_at >= start_date)
        if end_date:
            stmt = stmt.where(AuditLog.created_at <= end_date)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_audit_log_count(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        stmt = (
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.tenant_id == self.tenant_id)
        )
        if start_date:
            stmt = stmt.where(AuditLog.created_at >= start_date)
        if end_date:
            stmt = stmt.where(AuditLog.created_at <= end_date)
        result = await self.db.execute(stmt)
        return result.scalar()

    async def get_escalations(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = "pending",
    ) -> list:
        stmt = (
            select(Escalation)
            .where(Escalation.tenant_id == self.tenant_id)
            .order_by(Escalation.created_at.asc())
            .limit(limit)
            .offset(offset)
        )
        if status_filter:
            stmt = stmt.where(Escalation.status == status_filter)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_escalations_count(self, status_filter: Optional[str] = None) -> int:
        stmt = (
            select(func.count())
            .select_from(Escalation)
            .where(Escalation.tenant_id == self.tenant_id)
        )
        if status_filter:
            stmt = stmt.where(Escalation.status == status_filter)
        result = await self.db.execute(stmt)
        return result.scalar()

    async def get_pending_escalations(self, limit: int = 50, offset: int = 0) -> list:
        return await self.get_escalations(limit=limit, offset=offset, status_filter="pending")

    async def get_expired_pending_escalations(self):
        from datetime import datetime, timezone
        stmt = (
            select(Escalation)
            .where(
                Escalation.tenant_id == self.tenant_id,
                Escalation.status == "pending",
                Escalation.expires_at <= datetime.now(timezone.utc),
            )
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()
