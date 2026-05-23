"""
SentinelX IDS - Audit Log Routes

GET  /audit              – Paginated audit log with filters
GET  /audit/stats        – Action counts, top users, recent activity
GET  /audit/actions      – List of all valid action names
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user, require_role
from backend.database import get_db
from backend.models import AuditAction, AuditLog, User

router = APIRouter(prefix="/audit", tags=["Audit Log"])


# ─── Schemas (inline — lightweight) ──────────────────────────────────────────

def _row_to_dict(entry: AuditLog) -> dict:
    return {
        "id":            entry.id,
        "username":      entry.username,
        "user_role":     entry.user_role,
        "action":        entry.action.value,
        "resource_type": entry.resource_type,
        "resource_id":   entry.resource_id,
        "description":   entry.description,
        "extra":         entry.extra,
        "ip_address":    entry.ip_address,
        "user_agent":    entry.user_agent,
        "status":        entry.status,
        "timestamp":     entry.timestamp.isoformat() if entry.timestamp else None,
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("", summary="Paginated audit log")
async def list_audit_logs(
    # Filters
    username:      Optional[str] = Query(default=None),
    action:        Optional[str] = Query(default=None, description="Exact action name, e.g. alert_update"),
    resource_type: Optional[str] = Query(default=None, description="e.g. alert, rule, ioc"),
    status:        Optional[str] = Query(default=None, description="success | failure"),
    search:        Optional[str] = Query(default=None, description="Search in description"),
    start_time:    Optional[datetime] = Query(default=None),
    end_time:      Optional[datetime] = Query(default=None),
    # Pagination
    page:      int = Query(default=1,  ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return paginated, filterable audit log entries. Admin / analyst only."""
    q = select(AuditLog)

    if username:
        q = q.where(AuditLog.username.ilike(f"%{username}%"))
    if action:
        try:
            q = q.where(AuditLog.action == AuditAction(action))
        except ValueError:
            pass
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if status:
        q = q.where(AuditLog.status == status)
    if search:
        q = q.where(AuditLog.description.ilike(f"%{search}%"))
    if start_time:
        q = q.where(AuditLog.timestamp >= start_time)
    if end_time:
        q = q.where(AuditLog.timestamp <= end_time)

    # Count
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Page
    q = q.order_by(desc(AuditLog.timestamp)).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()

    return {
        "items":       [_row_to_dict(r) for r in rows],
        "total":       total,
        "page":        page,
        "page_size":   page_size,
        "total_pages": max(1, ceil(total / page_size)),
    }


@router.get("/stats", summary="Audit log statistics")
async def audit_stats(
    days: int = Query(default=7, ge=1, le=90, description="Lookback window in days"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return aggregate stats: total events, by action, by user, by status, recent trend."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Total
    total = (await db.execute(select(func.count(AuditLog.id)))).scalar_one()
    total_window = (await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= cutoff)
    )).scalar_one()

    # By action
    action_rows = (await db.execute(
        select(AuditLog.action, func.count(AuditLog.id).label("c"))
        .where(AuditLog.timestamp >= cutoff)
        .group_by(AuditLog.action)
        .order_by(desc("c"))
    )).all()
    by_action = {r[0].value: r[1] for r in action_rows}

    # By user
    user_rows = (await db.execute(
        select(AuditLog.username, func.count(AuditLog.id).label("c"))
        .where(AuditLog.timestamp >= cutoff)
        .group_by(AuditLog.username)
        .order_by(desc("c"))
        .limit(10)
    )).all()
    by_user = [{"username": r[0], "count": r[1]} for r in user_rows]

    # By status
    status_rows = (await db.execute(
        select(AuditLog.status, func.count(AuditLog.id).label("c"))
        .where(AuditLog.timestamp >= cutoff)
        .group_by(AuditLog.status)
    )).all()
    by_status = {r[0]: r[1] for r in status_rows}

    # By resource type
    resource_rows = (await db.execute(
        select(AuditLog.resource_type, func.count(AuditLog.id).label("c"))
        .where(AuditLog.timestamp >= cutoff, AuditLog.resource_type.isnot(None))
        .group_by(AuditLog.resource_type)
        .order_by(desc("c"))
    )).all()
    by_resource = {r[0]: r[1] for r in resource_rows}

    # Failures
    failures = (await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= cutoff, AuditLog.status == "failure")
    )).scalar_one()

    return {
        "total_all_time":  total,
        "total_in_window": total_window,
        "window_days":     days,
        "failures":        failures,
        "by_action":       by_action,
        "by_user":         by_user,
        "by_status":       by_status,
        "by_resource":     by_resource,
    }


@router.get("/actions", summary="List all valid audit action names")
async def list_actions(
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return all valid AuditAction values grouped by category."""
    groups = {
        "Authentication": ["login", "logout", "login_failed"],
        "Alerts":         ["alert_view", "alert_update", "alert_create", "alert_delete"],
        "Rules":          ["rule_create", "rule_update", "rule_delete", "rule_toggle"],
        "Threat Intel":   ["ioc_create", "ioc_update", "ioc_delete", "ioc_lookup", "ip_block", "ip_unblock", "feed_sync"],
        "Investigations": ["investigation_create", "investigation_update"],
        "Notifications":  ["notification_test"],
        "System":         ["settings_view", "export", "system"],
    }
    return [{"category": cat, "actions": acts} for cat, acts in groups.items()]
