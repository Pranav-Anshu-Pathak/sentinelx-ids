"""Log ingestion pipeline: parse → store → detect → notify → broadcast."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from alerts.notifier import notify_alert
from backend.database import async_session
from backend.models import Alert, AlertStatus, LogEntry, LogSource, Rule, Severity
from backend.ai_service import score_event_details
from detection_engine.engine import DetectionEngine
from parsers import SyslogParser
from parsers.base_parser import ParsedEvent
from websocket.manager import ConnectionManager

logger = logging.getLogger("sentinelx.pipeline")

_PARSERS = {"syslog": SyslogParser()}
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _parse_log_message(raw: str) -> str:
    parts: list[str] = []
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    if ips:
        parts.append(f"IPs: {', '.join(set(ips))}")
    keywords = ["failed", "denied", "error", "blocked", "scan", "malware", "intrusion"]
    found = [kw for kw in keywords if kw in raw.lower()]
    if found:
        parts.append(f"Keywords: {', '.join(found)}")
    return " | ".join(parts) if parts else "No structured data extracted"


def _log_source(value: str) -> LogSource:
    try:
        return LogSource(value.lower())
    except ValueError:
        return LogSource.SYSLOG


def _severity(value: str) -> Severity:
    return _SEVERITY_MAP.get(value.lower(), Severity.INFO)


async def process_event(
    event: dict[str, Any],
    detection_engine: DetectionEngine,
    ws_manager: Optional[ConnectionManager] = None,
) -> dict[str, Any]:
    """Ingest one event through the full pipeline."""
    raw = event.get("raw_message") or event.get("message", "")
    source_str = event.get("source", "syslog")

    parsed_event: Optional[ParsedEvent] = None
    parser = _PARSERS.get(source_str)
    if parser and raw:
        try:
            parsed_event = parser.parse(raw)
        except Exception:
            parsed_event = None

    source_ip = event.get("source_ip") or (parsed_event.source_ip if parsed_event else None)
    dest_ip = event.get("dest_ip") or (parsed_event.dest_ip if parsed_event else None)
    hostname = event.get("hostname") or (parsed_event.hostname if parsed_event else None)
    severity_str = event.get("severity") or (
        parsed_event.severity if parsed_event and parsed_event.severity else "info"
    )

    log_id: Optional[int] = None
    alert_ids: list[int] = []

    async with async_session() as db:
        entry = LogEntry(
            raw_message=raw,
            parsed_message=_parse_log_message(raw),
            source=_log_source(source_str),
            source_ip=source_ip,
            dest_ip=dest_ip,
            hostname=hostname,
            severity=_severity(severity_str),
            service=event.get("service"),
            event_type=event.get("event_type"),
            timestamp=event.get("timestamp") or datetime.now(timezone.utc),
        )
        db.add(entry)
        await db.flush()
        await db.refresh(entry)
        log_id = entry.id

        det_event = {
            "source_ip": source_ip or "",
            "dest_ip": dest_ip or "",
            "hostname": hostname or "",
            "message": raw,
            "service": event.get("service", ""),
            "event_type": event.get("event_type", ""),
            "severity": severity_str,
            "timestamp": entry.timestamp,
            "source": source_str,
        }
        # Feed anomaly scorer baseline (UI uses /ai/score-event)
        score_event_details(det_event)

        engine_alerts = await detection_engine.process_event(det_event)

        for eng_alert in engine_alerts:
            rule_db_id = await _resolve_rule_id(db, eng_alert.rule_id)
            if rule_db_id:
                rule = await db.get(Rule, rule_db_id)
                if rule:
                    rule.hits += 1

            db_alert = Alert(
                title=f"{eng_alert.rule_name}",
                description=eng_alert.message[:2000],
                severity=_severity(eng_alert.severity),
                status=AlertStatus.OPEN,
                source_ip=eng_alert.source_ip or source_ip,
                dest_ip=eng_alert.dest_ip or dest_ip,
                hostname=eng_alert.hostname or hostname,
                mitre_technique=eng_alert.mitre_technique,
                mitre_tactic=eng_alert.mitre_tactic,
                risk_score=min(100.0, eng_alert.risk_score),
                rule_id=rule_db_id,
            )
            db.add(db_alert)
            await db.flush()
            await db.refresh(db_alert)
            alert_ids.append(db_alert.id)

            alert_payload = {
                "type": "alert",
                "id": db_alert.id,
                "title": db_alert.title,
                "severity": db_alert.severity.value,
                "source_ip": db_alert.source_ip,
                "dest_ip": db_alert.dest_ip,
                "hostname": db_alert.hostname,
                "risk_score": db_alert.risk_score,
                "description": db_alert.description,
                "mitre_technique": db_alert.mitre_technique,
                "mitre_tactic": db_alert.mitre_tactic,
            }
            if ws_manager:
                await ws_manager.broadcast("events", alert_payload)
            await notify_alert(alert_payload)

        await db.commit()

    log_payload = {
        "type": "log",
        "id": log_id,
        "raw_message": raw[:500],
        "source": source_str,
        "source_ip": source_ip,
        "hostname": hostname,
        "severity": severity_str,
    }
    if ws_manager:
        await ws_manager.broadcast("events", log_payload)

    return {"log_id": log_id, "alert_ids": alert_ids}


async def _resolve_rule_id(db: AsyncSession, yaml_rule_id: str) -> Optional[int]:
    """Map YAML rule id (e.g. SX-1001) to database Rule.id via name pattern."""
    result = await db.execute(select(Rule).where(Rule.name.ilike(f"%{yaml_rule_id}%")))
    rule = result.scalar_one_or_none()
    if rule:
        return rule.id
    result = await db.execute(select(Rule))
    for r in result.scalars().all():
        if r.yaml_content and yaml_rule_id in r.yaml_content:
            return r.id
    return None
