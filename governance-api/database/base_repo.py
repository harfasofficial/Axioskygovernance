# database/base_repo.py
"""
TenantScopedRepo -- Layer 2 tenant isolation.
All database access goes through this base class.
Every query is structurally scoped to a tenant_id -- it is impossible
to query data without a tenant filter.
"""
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import AuditLog, Escalation


class TenantScopedRepo:
    """
    Base class for all database repositories.
    Enforces tenant isolation at the ORM layer -- structurally impossible
    to query data without a tenant_id filter.
    """

    def __init__(self, tenant_id: str, db: AsyncSession):
        self.tenant_id = tenant_id
        self.db = db

    async def get_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
        status_filter: str = None,
        agent_id: str = None,
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
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def get_audit_log_count(self) -> int:
        stmt = (
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.tenant_id == self.tenant_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar()

    async def get_pending_escalations(self, limit: int = 500, offset: int = 0) -> list:
        stmt = (
            select(Escalation)
            .where(
                Escalation.tenant_id == self.tenant_id,
                Escalation.status == "pending",
            )
            .order_by(Escalation.created_at.asc())
            .limit(limit)
            .offset(offset)
        )
        result = await self.db.execute(stmt)
        return result.scalars().all()

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
