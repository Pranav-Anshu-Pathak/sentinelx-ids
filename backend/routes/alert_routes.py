"""
SentinelX IDS - Alert Routes

GET   /alerts           – Paginated alerts with filters
GET   /alerts/stats     – Alert statistics
GET   /alerts/{id}      – Single alert detail
PATCH /alerts/{id}      – Update alert status/assignment
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, case, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, AlertStatus, Severity, User
from backend.schemas import (
    AlertCreate,
    AlertResponse,
    AlertStatsResponse,
    AlertStatusEnum,
    AlertUpdate,
    PaginatedResponse,
    SeverityEnum,
)
from backend.audit import audit
from backend.models import AuditAction
from fastapi import Request

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get(
    "",
    response_model=PaginatedResponse[AlertResponse],
    summary="List alerts",
)
async def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    severity: Optional[SeverityEnum] = Query(default=None),
    alert_status: Optional[AlertStatusEnum] = Query(default=None, alias="status"),
    mitre_technique: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[AlertResponse]:
    """Return a paginated list of alerts with optional filters."""
    query: Select = select(Alert)

    if severity:
        query = query.where(Alert.severity == Severity(severity.value))
    if alert_status:
        query = query.where(Alert.status == AlertStatus(alert_status.value))
    if mitre_technique:
        query = query.where(Alert.mitre_technique == mitre_technique)
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if hostname:
        query = query.where(Alert.hostname.ilike(f"%{hostname}%"))
    if start_time:
        query = query.where(Alert.created_at >= start_time)
    if end_time:
        query = query.where(Alert.created_at <= end_time)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    query = query.order_by(desc(Alert.created_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return PaginatedResponse[AlertResponse](
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, ceil(total / page_size)),
    )


@router.get(
    "/stats",
    response_model=AlertStatsResponse,
    summary="Alert statistics",
)
async def alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertStatsResponse:
    """Return aggregated alert statistics."""
    # Total count
    total = (await db.execute(select(func.count(Alert.id)))).scalar_one()

    # By severity
    sev_rows = (
        await db.execute(
            select(Alert.severity, func.count(Alert.id))
            .group_by(Alert.severity)
        )
    ).all()
    by_severity: dict[str, int] = {row[0].value: row[1] for row in sev_rows}

    # By status
    status_rows = (
        await db.execute(
            select(Alert.status, func.count(Alert.id))
            .group_by(Alert.status)
        )
    ).all()
    by_status: dict[str, int] = {row[0].value: row[1] for row in status_rows}

    # Top source IPs
    top_ips_rows = (
        await db.execute(
            select(Alert.source_ip, func.count(Alert.id).label("count"))
            .where(Alert.source_ip.isnot(None))
            .group_by(Alert.source_ip)
            .order_by(desc("count"))
            .limit(10)
        )
    ).all()
    top_source_ips: list[dict[str, Any]] = [
        {"ip": row[0], "count": row[1]} for row in top_ips_rows
    ]

    # Top MITRE techniques
    top_mitre_rows = (
        await db.execute(
            select(Alert.mitre_technique, func.count(Alert.id).label("count"))
            .where(Alert.mitre_technique.isnot(None))
            .group_by(Alert.mitre_technique)
            .order_by(desc("count"))
            .limit(10)
        )
    ).all()
    top_mitre_techniques: list[dict[str, Any]] = [
        {"technique": row[0], "count": row[1]} for row in top_mitre_rows
    ]

    # Recent 24h
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.created_at >= cutoff)
        )
    ).scalar_one()

    return AlertStatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        top_source_ips=top_source_ips,
        top_mitre_techniques=top_mitre_techniques,
        recent_24h=recent,
    )


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert detail",
)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Return a single alert by ID with related investigation data."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id {alert_id} not found",
        )

    return AlertResponse.model_validate(alert)


@router.patch(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update alert",
)
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Update an alert's status, assignment, severity, or risk score."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id {alert_id} not found",
        )

    changes = {}
    if update.status is not None:
        changes["status"] = {"from": alert.status.value, "to": update.status.value}
        alert.status = AlertStatus(update.status.value)
    if update.assigned_to is not None:
        changes["assigned_to"] = {"from": alert.assigned_to, "to": update.assigned_to}
        alert.assigned_to = update.assigned_to
    if update.severity is not None:
        changes["severity"] = {"from": alert.severity.value, "to": update.severity.value}
        alert.severity = Severity(update.severity.value)
    if update.risk_score is not None:
        changes["risk_score"] = {"from": alert.risk_score, "to": update.risk_score}
        alert.risk_score = update.risk_score

    alert.updated_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(alert)
    await audit(db, current_user, AuditAction.ALERT_UPDATE,
                resource_type="alert", resource_id=str(alert_id),
                description=f"Updated alert #{alert_id}: {', '.join(f'{k}→{v["to"]}' for k, v in changes.items())}",
                extra={"changes": changes}, request=request)
    return AlertResponse.model_validate(alert)


@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create alert manually",
)
async def create_alert(
    alert_in: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertResponse:
    """Manually create a new alert."""
    alert = Alert(
        title=alert_in.title,
        description=alert_in.description,
        severity=Severity(alert_in.severity.value),
        status=AlertStatus.OPEN,
        source_ip=alert_in.source_ip,
        dest_ip=alert_in.dest_ip,
        hostname=alert_in.hostname,
        mitre_technique=alert_in.mitre_technique,
        mitre_tactic=alert_in.mitre_tactic,
        risk_score=alert_in.risk_score,
        rule_id=alert_in.rule_id,
        geo_country=alert_in.geo_country,
        geo_city=alert_in.geo_city,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)
