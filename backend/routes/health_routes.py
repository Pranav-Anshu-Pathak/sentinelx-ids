"""
SentinelX IDS - Health & Metrics Routes

GET /health  – System health (DB status, uptime, version)
GET /metrics – Real-time metrics (event rates, totals, resource usage)
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.database import get_db
from backend.models import Alert, AlertStatus, LogEntry, Rule, Severity
from backend.schemas import HealthResponse, MetricsResponse

router = APIRouter(tags=["Health & Metrics"])

# Module-level start time for uptime calculation
_START_TIME: float = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System health check",
)
async def health_check(
    db: AsyncSession = Depends(get_db),
) -> HealthResponse:
    """Return the system health status including database connectivity and uptime."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=settings.APP_VERSION,
        uptime_seconds=round(time.time() - _START_TIME, 2),
        database=db_status,
        demo_mode=settings.DEMO_MODE,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Real-time metrics",
)
async def get_metrics(
    db: AsyncSession = Depends(get_db),
) -> MetricsResponse:
    """Return real-time system metrics."""
    # Total logs
    total_logs: int = (
        await db.execute(select(func.count(LogEntry.id)))
    ).scalar_one()

    # Total alerts
    total_alerts: int = (
        await db.execute(select(func.count(Alert.id)))
    ).scalar_one()

    # Active (enabled) rules
    active_rules: int = (
        await db.execute(
            select(func.count(Rule.id)).where(Rule.enabled == True)  # noqa: E712
        )
    ).scalar_one()

    # Open alerts
    open_alerts: int = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
        )
    ).scalar_one()

    # Critical alerts
    critical_alerts: int = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == Severity.CRITICAL)
        )
    ).scalar_one()

    # Events per second (approximate: logs in last 60 seconds / 60)
    now = datetime.now(timezone.utc)
    from datetime import timedelta

    recent_cutoff = now - timedelta(seconds=60)
    recent_count: int = (
        await db.execute(
            select(func.count(LogEntry.id)).where(
                LogEntry.created_at >= recent_cutoff
            )
        )
    ).scalar_one()
    events_per_second = round(recent_count / 60.0, 2)

    # Resource usage (best effort on the platform)
    try:
        import psutil
        process = psutil.Process(os.getpid())
        memory_mb = round(process.memory_info().rss / (1024 * 1024), 2)
        cpu_percent = process.cpu_percent(interval=0.1)
    except ImportError:
        # psutil not available – provide estimates
        memory_mb = 0.0
        cpu_percent = 0.0

    return MetricsResponse(
        events_per_second=events_per_second,
        total_logs=total_logs,
        total_alerts=total_alerts,
        active_rules=active_rules,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        memory_usage_mb=memory_mb,
        cpu_usage_percent=cpu_percent,
        timestamp=now,
    )
