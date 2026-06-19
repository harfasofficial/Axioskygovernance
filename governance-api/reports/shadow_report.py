# reports/shadow_report.py
from datetime import datetime, timezone
from typing import Dict, Optional

from sqlalchemy import func, case
from sqlalchemy import select

from database.models import AuditLog
from database.session import AsyncSessionLocal


class ShadowReport:
    """
    Generates the 30-day shadow mode pilot report.
    Uses database-level aggregation for performance.
    """

    SHADOW_LIMIT = 50000  # Maximum entries to process

    async def generate(
        self,
        tenant_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        async with AsyncSessionLocal() as db:
            # Use database-level aggregation for counts
            count_stmt = (
                select(
                    func.count().label("total"),
                    func.count(case((AuditLog.status == "APPROVE", 1))).label("approved"),
                    func.count(case((AuditLog.status == "BLOCK", 1))).label("blocked"),
                    func.count(case((AuditLog.status == "ESCALATE", 1))).label("escalated"),
                )
                .where(AuditLog.tenant_id == tenant_id)
                .where(AuditLog.environment == "shadow")
            )

            if start_date:
                count_stmt = count_stmt.where(AuditLog.created_at >= start_date)
            if end_date:
                count_stmt = count_stmt.where(AuditLog.created_at <= end_date)

            count_result = await db.execute(count_stmt)
            counts = count_result.one()

            total = counts.total or 0
            approved = counts.approved or 0
            blocked = counts.blocked or 0
            escalated = counts.escalated or 0
            violations = blocked + escalated
            violation_rate = round((violations / total) * 100, 2) if total else 0.0

            if total == 0:
                return {
                    "tenant_id": tenant_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "truncated": False,
                    "summary": {
                        "total_decisions": 0,
                        "would_have_approved": 0,
                        "would_have_blocked": 0,
                        "would_have_escalated": 0,
                        "violation_rate_pct": 0.0,
                        "message": "No shadow decisions found.",
                    },
                }

            # Load limited entries for breakdown by agent/rule
            stmt = (
                select(AuditLog)
                .where(AuditLog.tenant_id == tenant_id)
                .where(AuditLog.environment == "shadow")
                .order_by(AuditLog.created_at.asc())
                .limit(self.SHADOW_LIMIT)
            )

            if start_date:
                stmt = stmt.where(AuditLog.created_at >= start_date)
            if end_date:
                stmt = stmt.where(AuditLog.created_at <= end_date)

            entries_result = await db.execute(stmt)
            entries = entries_result.scalars().all()

        truncated = total > self.SHADOW_LIMIT

        # Build by-agent breakdown
        by_agent: Dict[str, dict] = {}
        for e in entries:
            agent_stats = by_agent.setdefault(
                e.agent_id,
                {
                    "agent_id": e.agent_id,
                    "total": 0,
                    "approved": 0,
                    "blocked": 0,
                    "escalated": 0,
                },
            )
            agent_stats["total"] += 1
            key_map = {"APPROVE": "approved", "BLOCK": "blocked", "ESCALATE": "escalated"}
            agent_stats[key_map.get(e.status, e.status.lower())] += 1

        # Build by-rule breakdown
        by_rule: Dict[str, dict] = {}
        for e in entries:
            if not e.rule_triggered:
                continue
            rule_stats = by_rule.setdefault(
                e.rule_triggered,
                {
                    "rule_id": e.rule_triggered,
                    "trigger_count": 0,
                    "reason": e.reason,
                    "reason_code": e.reason_code,
                },
            )
            rule_stats["trigger_count"] += 1

        # Violations list (limited)
        violations_list = [
            {
                "decision_id": e.decision_id,
                "agent_id": e.agent_id,
                "action_type": e.action_type,
                "status": e.status,
                "rule_triggered": e.rule_triggered,
                "reason": e.reason,
                "reason_code": e.reason_code,
                "timestamp": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
            if e.status in ("BLOCK", "ESCALATE")
        ]

        return {
            "tenant_id": tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "truncated": truncated,
            "summary": {
                "total_decisions": total,
                "would_have_approved": approved,
                "would_have_blocked": blocked,
                "would_have_escalated": escalated,
                "violation_rate_pct": violation_rate,
            },
            "by_agent": list(by_agent.values()),
            "top_rules": sorted(
                by_rule.values(),
                key=lambda item: item["trigger_count"],
                reverse=True,
            ),
            "violations": violations_list,
        }


shadow_report = ShadowReport()
