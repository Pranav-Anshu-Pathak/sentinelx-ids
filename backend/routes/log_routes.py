"""
SentinelX IDS - Log Ingestion & Query Routes

POST /logs/ingest – Ingest single or batch log entries
GET  /logs        – Paginated log listing with filters
GET  /logs/search – Full-text search
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from math import ceil
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, AlertStatus, LogEntry, LogSource, Rule, Severity, User
from backend.schemas import (
    AlertCreate,
    LogBatchIngest,
    LogIngest,
    LogResponse,
    LogSearchQuery,
    LogSourceEnum,
    PaginatedResponse,
    SeverityEnum,
)

router = APIRouter(prefix="/logs", tags=["Logs"])


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _parse_log_message(raw: str) -> str:
    """Simple heuristic parser that extracts structured info from a raw log line."""
    parsed_parts: list[str] = []

    # Try to extract IP addresses
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ips = re.findall(ip_pattern, raw)
    if ips:
        parsed_parts.append(f"IPs: {', '.join(set(ips))}")

    # Try to extract common event keywords
    keywords = [
        "failed", "denied", "error", "warning", "success", "accepted",
        "blocked", "dropped", "rejected", "timeout", "unauthorized",
        "malware", "intrusion", "scan", "brute", "overflow",
    ]
    found_keywords = [kw for kw in keywords if kw.lower() in raw.lower()]
    if found_keywords:
        parsed_parts.append(f"Keywords: {', '.join(found_keywords)}")

    # Try to extract port numbers
    port_pattern = r"port\s+(\d+)"
    ports = re.findall(port_pattern, raw, re.IGNORECASE)
    if ports:
        parsed_parts.append(f"Ports: {', '.join(set(ports))}")

    # Try to extract usernames
    user_pattern = r"(?:user|for)\s+(\w+)"
    users = re.findall(user_pattern, raw, re.IGNORECASE)
    if users:
        parsed_parts.append(f"Users: {', '.join(set(users))}")

    return " | ".join(parsed_parts) if parsed_parts else "No structured data extracted"


async def _run_detection(log_entry: LogEntry, db: AsyncSession) -> None:
    """Run all enabled detection rules against a log entry and create alerts on match."""
    result = await db.execute(select(Rule).where(Rule.enabled == True))  # noqa: E712
    rules = result.scalars().all()

    for rule in rules:
        if rule.pattern and re.search(rule.pattern, log_entry.raw_message, re.IGNORECASE):
            # Increment hit counter
            rule.hits += 1

            # Determine severity from rule
            severity = rule.severity

            alert = Alert(
                title=f"Rule Match: {rule.name}",
                description=(
                    f"Detection rule '{rule.name}' matched log entry.\n"
                    f"Pattern: {rule.pattern}\n"
                    f"Log: {log_entry.raw_message[:500]}"
                ),
                severity=severity,
                status=AlertStatus.OPEN,
                source_ip=log_entry.source_ip,
                dest_ip=log_entry.dest_ip,
                hostname=log_entry.hostname,
                mitre_technique=rule.mitre_technique,
                risk_score=_calculate_risk_score(severity),
                rule_id=rule.id,
            )
            db.add(alert)

    await db.flush()


def _calculate_risk_score(severity: Severity) -> float:
    """Map severity to a numeric risk score."""
    severity_scores = {
        Severity.CRITICAL: 95.0,
        Severity.HIGH: 80.0,
        Severity.MEDIUM: 55.0,
        Severity.LOW: 30.0,
        Severity.INFO: 10.0,
    }
    return severity_scores.get(severity, 50.0)


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/ingest",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest log entries",
)
async def ingest_logs(
    payload: LogIngest | LogBatchIngest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Ingest a single log entry or a batch of log entries.

    Each log is parsed, stored in the database, and run through the
    detection engine to generate alerts.
    """
    # Normalise to a list
    if isinstance(payload, LogIngest):
        logs_in = [payload]
    else:
        logs_in = payload.logs

    created_ids: list[int] = []
    alerts_generated: int = 0

    for log_data in logs_in:
        parsed = _parse_log_message(log_data.raw_message)

        entry = LogEntry(
            raw_message=log_data.raw_message,
            parsed_message=parsed,
            source=LogSource(log_data.source.value),
            source_ip=log_data.source_ip,
            dest_ip=log_data.dest_ip,
            hostname=log_data.hostname,
            severity=Severity(log_data.severity.value),
            service=log_data.service,
            event_type=log_data.event_type,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.flush()
        await db.refresh(entry)
        created_ids.append(entry.id)

        # Count alerts before and after detection
        alert_count_before = (
            await db.execute(select(func.count(Alert.id)))
        ).scalar_one()
        await _run_detection(entry, db)
        alert_count_after = (
            await db.execute(select(func.count(Alert.id)))
        ).scalar_one()
        alerts_generated += alert_count_after - alert_count_before

    return {
        "status": "accepted",
        "logs_ingested": len(created_ids),
        "log_ids": created_ids,
        "alerts_generated": alerts_generated,
    }


@router.get(
    "",
    response_model=PaginatedResponse[LogResponse],
    summary="List log entries",
)
async def list_logs(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=200, description="Items per page"),
    severity: Optional[SeverityEnum] = Query(default=None),
    source: Optional[LogSourceEnum] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    dest_ip: Optional[str] = Query(default=None),
    start_time: Optional[datetime] = Query(default=None),
    end_time: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[LogResponse]:
    """Return a paginated list of log entries with optional filters."""
    query: Select = select(LogEntry)

    if severity:
        query = query.where(LogEntry.severity == Severity(severity.value))
    if source:
        query = query.where(LogEntry.source == LogSource(source.value))
    if hostname:
        query = query.where(LogEntry.hostname.ilike(f"%{hostname}%"))
    if source_ip:
        query = query.where(LogEntry.source_ip == source_ip)
    if dest_ip:
        query = query.where(LogEntry.dest_ip == dest_ip)
    if start_time:
        query = query.where(LogEntry.timestamp >= start_time)
    if end_time:
        query = query.where(LogEntry.timestamp <= end_time)

    # Count total
    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Fetch page
    query = query.order_by(desc(LogEntry.timestamp)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    logs = result.scalars().all()

    return PaginatedResponse[LogResponse](
        items=[LogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, ceil(total / page_size)),
    )


@router.get(
    "/search",
    response_model=PaginatedResponse[LogResponse],
    summary="Search logs",
)
async def search_logs(
    q: str = Query(..., min_length=1, description="Search query string"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedResponse[LogResponse]:
    """Full-text search across raw_message, parsed_message, hostname, and IPs."""
    search_term = f"%{q}%"

    query = select(LogEntry).where(
        or_(
            LogEntry.raw_message.ilike(search_term),
            LogEntry.parsed_message.ilike(search_term),
            LogEntry.hostname.ilike(search_term),
            LogEntry.source_ip.ilike(search_term),
            LogEntry.dest_ip.ilike(search_term),
            LogEntry.service.ilike(search_term),
            LogEntry.event_type.ilike(search_term),
        )
    )

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    query = query.order_by(desc(LogEntry.timestamp)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    logs = result.scalars().all()

    return PaginatedResponse[LogResponse](
        items=[LogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, ceil(total / page_size)),
    )
