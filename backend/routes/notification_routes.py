"""
SentinelX IDS - Notification Management Routes

GET  /notifications/config          – Channel config status (no secrets)
GET  /notifications/history         – Last 200 notifications sent
POST /notifications/test            – Send a test notification
POST /notifications/test/{channel}  – Test a specific channel (slack|discord|email)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from backend.auth import get_current_user, require_role
from backend.models import User
from alerts.notifier import (
    get_notification_config_status,
    get_notification_history,
    send_test_notification,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("/config", summary="Notification channel configuration status")
async def notification_config(
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Return which notification channels are configured.
    Does NOT expose webhook URLs or passwords.
    """
    return get_notification_config_status()


@router.get("/history", summary="Notification dispatch history")
async def notification_history(
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return the last 200 notification events (sent, skipped, errors)."""
    return get_notification_history()


@router.post("/test", summary="Send a test notification to all configured channels")
async def test_all_notifications(
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Fire a test notification to every configured channel at once."""
    return await send_test_notification(channel=None)


@router.post("/test/{channel}", summary="Send a test notification to a specific channel")
async def test_single_channel(
    channel: str,
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """
    Send a test notification to a specific channel.
    channel: slack | discord | email
    """
    valid = {"slack", "discord", "email"}
    if channel not in valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid channel '{channel}'. Must be one of: {', '.join(valid)}",
        )
    return await send_test_notification(channel=channel)
