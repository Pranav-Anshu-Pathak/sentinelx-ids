"""Dashboard summary endpoint."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, AlertStatus, LogEntry, Rule, Severity, User
from backend.schemas import AlertResponse, LogResponse

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard", summary="Dashboard summary")
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Aggregated data for the main dashboard."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    total_logs = (await db.execute(select(func.count(LogEntry.id)))).scalar_one()
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar_one()
    open_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
        )
    ).scalar_one()
    critical_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == Severity.CRITICAL)
        )
    ).scalar_one()
    active_rules = (
        await db.execute(select(func.count(Rule.id)).where(Rule.enabled == True))  # noqa: E712
    ).scalar_one()
    recent_alerts_24h = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.created_at >= cutoff)
        )
    ).scalar_one()

    recent_logs = (
        await db.execute(
            select(LogEntry).order_by(desc(LogEntry.timestamp)).limit(10)
        )
    ).scalars().all()

    recent_alert_rows = (
        await db.execute(
            select(Alert).order_by(desc(Alert.created_at)).limit(8)
        )
    ).scalars().all()

    by_severity: dict[str, int] = {}
    for sev in Severity:
        count = (
            await db.execute(
                select(func.count(Alert.id)).where(Alert.severity == sev)
            )
        ).scalar_one()
        by_severity[sev.value] = count

    return {
        "metrics": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "active_rules": active_rules,
            "recent_alerts_24h": recent_alerts_24h,
        },
        "alerts_by_severity": by_severity,
        "recent_logs": [LogResponse.model_validate(l) for l in recent_logs],
        "recent_alerts": [AlertResponse.model_validate(a) for a in recent_alert_rows],
        "timestamp": now.isoformat(),
    }
