"""
SentinelX IDS - Search Routes

POST /search/query       – Natural language search
GET  /search/suggestions – Common search query suggestions
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, AlertStatus, LogEntry, Severity, User
from backend.schemas import (
    LogResponse,
    AlertResponse,
    NLPSearchQuery,
    NLPSearchResponse,
    SearchSuggestion,
)

router = APIRouter(prefix="/search", tags=["Search"])


# ═══════════════════════════════════════════════════════════════════════════
# NLP Query Parser (rule-based, works without external AI)
# ═══════════════════════════════════════════════════════════════════════════

def _parse_nlp_query(query: str) -> dict[str, Any]:
    """Parse a natural language query into structured filters.

    This is a rule-based NLP parser that handles common security-related
    queries without requiring an external LLM. It extracts:
    - severity levels
    - time ranges
    - IP addresses
    - country references
    - attack types
    - MITRE technique IDs
    """
    filters: dict[str, Any] = {}
    query_lower = query.lower()

    # ── Severity extraction ──────────────────────────────────────────────
    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    for keyword, sev in severity_map.items():
        if keyword in query_lower:
            filters["severity"] = sev
            break

    # ── Time range extraction ────────────────────────────────────────────
    time_patterns = {
        r"last\s+(\d+)\s+hour": "hours",
        r"last\s+(\d+)\s+day": "days",
        r"last\s+(\d+)\s+minute": "minutes",
        r"past\s+(\d+)\s+hour": "hours",
        r"past\s+(\d+)\s+day": "days",
        r"last\s+24\s*h": "hours_24",
        r"today": "today",
        r"yesterday": "yesterday",
    }
    for pattern, unit in time_patterns.items():
        match = re.search(pattern, query_lower)
        if match:
            now = datetime.now(timezone.utc)
            if unit == "hours":
                filters["start_time"] = now - timedelta(hours=int(match.group(1)))
            elif unit == "days":
                filters["start_time"] = now - timedelta(days=int(match.group(1)))
            elif unit == "minutes":
                filters["start_time"] = now - timedelta(minutes=int(match.group(1)))
            elif unit == "hours_24":
                filters["start_time"] = now - timedelta(hours=24)
            elif unit == "today":
                filters["start_time"] = now.replace(hour=0, minute=0, second=0, microsecond=0)
            elif unit == "yesterday":
                yesterday = now - timedelta(days=1)
                filters["start_time"] = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
                filters["end_time"] = yesterday.replace(hour=23, minute=59, second=59)
            break

    # ── IP address extraction ────────────────────────────────────────────
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", query)
    if ip_match:
        filters["source_ip"] = ip_match.group(1)

    # ── Country extraction ───────────────────────────────────────────────
    countries = {
        "china": "CN", "chinese": "CN", "russia": "RU", "russian": "RU",
        "north korea": "KP", "iran": "IR", "united states": "US", "usa": "US",
        "germany": "DE", "france": "FR", "brazil": "BR", "india": "IN",
        "ukraine": "UA", "vietnam": "VN", "netherlands": "NL",
    }
    for country_name, code in countries.items():
        if country_name in query_lower:
            filters["geo_country"] = code
            break

    # ── Attack type mapping ──────────────────────────────────────────────
    attack_keywords = {
        "brute force": "brute_force",
        "brute-force": "brute_force",
        "ssh": "ssh_attack",
        "sql injection": "sql_injection",
        "sqli": "sql_injection",
        "xss": "xss",
        "cross-site": "xss",
        "port scan": "port_scan",
        "scanning": "port_scan",
        "malware": "malware",
        "ransomware": "ransomware",
        "phishing": "phishing",
        "ddos": "ddos",
        "denial of service": "ddos",
        "privilege escalation": "privilege_escalation",
        "lateral movement": "lateral_movement",
        "data exfiltration": "data_exfiltration",
        "exfil": "data_exfiltration",
    }
    for keyword, attack_type in attack_keywords.items():
        if keyword in query_lower:
            filters["attack_type"] = attack_type
            break

    # ── MITRE technique extraction ───────────────────────────────────────
    mitre_match = re.search(r"T\d{4}(?:\.\d{3})?", query, re.IGNORECASE)
    if mitre_match:
        filters["mitre_technique"] = mitre_match.group(0).upper()

    # ── Search text (remaining meaningful words) ─────────────────────────
    stop_words = {
        "show", "me", "all", "the", "from", "in", "with", "and", "or",
        "find", "get", "list", "display", "search", "for", "last", "past",
        "hours", "hour", "days", "day", "minutes", "minute", "that", "are",
        "were", "have", "has", "been", "a", "an", "to", "of", "by",
    }
    words = re.findall(r"\b\w+\b", query_lower)
    search_words = [w for w in words if w not in stop_words and len(w) > 2]
    if search_words:
        filters["search_text"] = " ".join(search_words)

    return filters


async def _execute_search(
    filters: dict[str, Any],
    db: AsyncSession,
) -> tuple[list[Any], int, str]:
    """Execute search based on parsed filters.

    Returns (results, total_count, search_type).
    """
    # Determine whether to search alerts or logs based on context
    search_alerts = any(
        k in filters for k in ["mitre_technique", "geo_country", "attack_type"]
    )

    if search_alerts:
        return await _search_alerts(filters, db)
    return await _search_logs(filters, db)


async def _search_logs(
    filters: dict[str, Any],
    db: AsyncSession,
) -> tuple[list[Any], int, str]:
    """Search log entries based on filters."""
    query = select(LogEntry)

    if "severity" in filters:
        query = query.where(LogEntry.severity == Severity(filters["severity"]))
    if "source_ip" in filters:
        query = query.where(LogEntry.source_ip == filters["source_ip"])
    if "start_time" in filters:
        query = query.where(LogEntry.timestamp >= filters["start_time"])
    if "end_time" in filters:
        query = query.where(LogEntry.timestamp <= filters["end_time"])
    if "search_text" in filters:
        term = f"%{filters['search_text']}%"
        query = query.where(
            or_(
                LogEntry.raw_message.ilike(term),
                LogEntry.parsed_message.ilike(term),
                LogEntry.hostname.ilike(term),
            )
        )

    query = query.order_by(desc(LogEntry.timestamp)).limit(100)
    result = await db.execute(query)
    logs = result.scalars().all()

    return (
        [LogResponse.model_validate(log).model_dump() for log in logs],
        len(logs),
        "logs",
    )


async def _search_alerts(
    filters: dict[str, Any],
    db: AsyncSession,
) -> tuple[list[Any], int, str]:
    """Search alerts based on filters."""
    query = select(Alert)

    if "severity" in filters:
        query = query.where(Alert.severity == Severity(filters["severity"]))
    if "source_ip" in filters:
        query = query.where(Alert.source_ip == filters["source_ip"])
    if "mitre_technique" in filters:
        query = query.where(Alert.mitre_technique == filters["mitre_technique"])
    if "geo_country" in filters:
        query = query.where(Alert.geo_country == filters["geo_country"])
    if "start_time" in filters:
        query = query.where(Alert.created_at >= filters["start_time"])
    if "end_time" in filters:
        query = query.where(Alert.created_at <= filters["end_time"])
    if "search_text" in filters:
        term = f"%{filters['search_text']}%"
        query = query.where(
            or_(
                Alert.title.ilike(term),
                Alert.description.ilike(term),
            )
        )

    query = query.order_by(desc(Alert.created_at)).limit(100)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return (
        [AlertResponse.model_validate(a).model_dump() for a in alerts],
        len(alerts),
        "alerts",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/query",
    response_model=NLPSearchResponse,
    summary="Natural language search",
)
async def nlp_search(
    body: NLPSearchQuery,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NLPSearchResponse:
    """Process a natural language query and return matching results.

    Uses a rule-based NLP parser to extract filters and then executes
    the appropriate database query. No external LLM required.
    """
    filters = _parse_nlp_query(body.query)
    results, total, search_type = await _execute_search(filters, db)

    # Build human-readable interpretation
    interpretations: list[str] = []
    if "severity" in filters:
        interpretations.append(f"severity={filters['severity']}")
    if "source_ip" in filters:
        interpretations.append(f"source_ip={filters['source_ip']}")
    if "mitre_technique" in filters:
        interpretations.append(f"mitre={filters['mitre_technique']}")
    if "geo_country" in filters:
        interpretations.append(f"country={filters['geo_country']}")
    if "start_time" in filters:
        interpretations.append(f"after={filters['start_time'].isoformat()}")
    if "attack_type" in filters:
        interpretations.append(f"attack_type={filters['attack_type']}")
    if "search_text" in filters:
        interpretations.append(f"text_contains='{filters['search_text']}'")

    interpreted = (
        f"Searching {search_type} with filters: {', '.join(interpretations)}"
        if interpretations
        else f"Broad {search_type} search"
    )

    return NLPSearchResponse(
        original_query=body.query,
        interpreted_query=interpreted,
        filters_applied=filters,
        results=results,
        total=total,
    )


@router.get(
    "/suggestions",
    response_model=list[SearchSuggestion],
    summary="Search suggestions",
)
async def search_suggestions(
    current_user: User = Depends(get_current_user),
) -> list[SearchSuggestion]:
    """Return a list of common search query suggestions."""
    return [
        SearchSuggestion(
            label="Critical alerts in the last 24 hours",
            query="Show me all critical alerts in the last 24 hours",
            category="alerts",
        ),
        SearchSuggestion(
            label="SSH brute force attacks",
            query="Find brute force SSH attacks",
            category="attacks",
        ),
        SearchSuggestion(
            label="Traffic from China",
            query="Show all alerts from China",
            category="geo",
        ),
        SearchSuggestion(
            label="Port scanning activity",
            query="Find port scan activity in the last 7 days",
            category="attacks",
        ),
        SearchSuggestion(
            label="High severity events today",
            query="Show high severity events today",
            category="severity",
        ),
        SearchSuggestion(
            label="Failed login attempts",
            query="Show me failed login attempts in the last hour",
            category="authentication",
        ),
        SearchSuggestion(
            label="MITRE T1110 (Brute Force)",
            query="Find alerts with MITRE technique T1110",
            category="mitre",
        ),
        SearchSuggestion(
            label="Malware detections",
            query="Show malware detections in the last 3 days",
            category="malware",
        ),
        SearchSuggestion(
            label="Data exfiltration alerts",
            query="Find data exfiltration activity",
            category="attacks",
        ),
        SearchSuggestion(
            label="All open alerts",
            query="List all open high severity alerts",
            category="alerts",
        ),
    ]
