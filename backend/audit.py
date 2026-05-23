"""
SentinelX IDS - Audit Logger

Provides a simple async helper to write immutable audit log entries.
Call `audit()` from any route to record user actions.

Usage:
    from backend.audit import audit
    await audit(db, user, AuditAction.ALERT_UPDATE,
                resource_type="alert", resource_id=str(alert_id),
                description=f"Status changed to {new_status}",
                request=request)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import AuditAction, AuditLog, User

logger = logging.getLogger("sentinelx.audit")


async def audit(
    db: AsyncSession,
    user: Optional[User],
    action: AuditAction,
    *,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    description: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
    request: Optional[Request] = None,
    status: str = "success",
) -> AuditLog:
    """
    Write a single audit log entry and flush it to the DB session.

    The caller is responsible for committing the session (the existing
    `get_db` dependency already auto-commits on success).

    Parameters
    ----------
    db            : active async DB session
    user          : authenticated User (None = system action)
    action        : AuditAction enum value
    resource_type : type of the object acted on (e.g. "alert", "rule", "ioc")
    resource_id   : string ID or value of the object
    description   : human-readable summary of what happened
    extra         : arbitrary JSON metadata (before/after values, counts, etc.)
    request       : FastAPI Request – used to extract client IP and user-agent
    status        : "success" | "failure"
    """
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    if request is not None:
        # Respect X-Forwarded-For from reverse proxies
        forwarded = request.headers.get("x-forwarded-for")
        ip_address = forwarded.split(",")[0].strip() if forwarded else request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")[:512]

    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "system",
        user_role=user.role.value if user else "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        description=description,
        extra=extra,
        ip_address=ip_address,
        user_agent=user_agent,
        status=status,
    )
    db.add(entry)
    await db.flush()

    logger.info(
        "[AUDIT] user=%s action=%s resource=%s/%s status=%s — %s",
        entry.username,
        action.value,
        resource_type or "-",
        resource_id or "-",
        status,
        description or "",
    )
    return entry


async def audit_system(
    db: AsyncSession,
    action: AuditAction,
    description: str,
    extra: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """Convenience wrapper for system-generated audit entries (no user context)."""
    return await audit(
        db,
        user=None,
        action=action,
        description=description,
        extra=extra,
        status="success",
    )
