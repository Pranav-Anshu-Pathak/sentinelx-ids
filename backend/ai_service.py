"""Shared AI/LLM service instances for SentinelX IDS."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ai_engine.anomaly_scorer import AnomalyScorer
from ai_engine.copilot import SOCCopilot
from ai_engine.llm_integration import LLMClient
from ai_engine.nlp_query import NLPQueryParser
from backend.config import settings
from backend.models import Alert

_copilot = SOCCopilot()
_nlp_parser = NLPQueryParser()
_anomaly_scorer = AnomalyScorer()
_llm_client: LLMClient | None = None


def get_copilot() -> SOCCopilot:
    return _copilot


def get_nlp_parser() -> NLPQueryParser:
    return _nlp_parser


def get_anomaly_scorer() -> AnomalyScorer:
    return _anomaly_scorer


def get_llm_client() -> LLMClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient(
            provider=settings.LLM_PROVIDER,
            api_key=settings.resolve_llm_api_key(),
        )
    return _llm_client


def reset_llm_client() -> None:
    """Recreate LLM client after config change."""
    global _llm_client
    _llm_client = None


def alert_to_context(alert: Alert) -> dict[str, Any]:
    """Convert ORM alert to copilot/LLM context dict."""
    return {
        "title": alert.title,
        "severity": alert.severity.value,
        "source_ip": alert.source_ip or "",
        "dest_ip": alert.dest_ip or "",
        "hostname": alert.hostname or "",
        "message": alert.description or alert.title,
        "mitre_technique": alert.mitre_technique or "",
        "mitre_tactic": alert.mitre_tactic or "",
        "risk_score": alert.risk_score,
        "rule_name": alert.title,
        "category": alert.mitre_tactic or "",
    }


def parsed_nlp_to_search_filters(parsed: dict[str, Any]) -> dict[str, Any]:
    """Map NLPQueryParser output to search_routes filter dict."""
    filters: dict[str, Any] = {}
    pf = parsed.get("filters") or {}
    query_type = parsed.get("type", "search")

    if query_type == "alerts":
        filters["_force_alerts"] = True

    if "severity" in pf:
        sev = pf["severity"]
        if sev == "informational":
            sev = "info"
        filters["severity"] = sev
    if "source_ip" in pf:
        filters["source_ip"] = pf["source_ip"]
    if "hostname" in pf:
        filters["search_text"] = pf["hostname"]
    if "message_contains" in pf:
        filters["search_text"] = pf["message_contains"]
    if "mitre_technique" in pf:
        filters["mitre_technique"] = pf["mitre_technique"]

    tr = pf.get("time_range")
    if tr:
        now = datetime.now(timezone.utc)
        m = re.match(r"(\d+)([mhdw])", str(tr))
        if m:
            n, unit = int(m.group(1)), m.group(2)
            deltas = {
                "m": timedelta(minutes=n),
                "h": timedelta(hours=n),
                "d": timedelta(days=n),
                "w": timedelta(weeks=n),
            }
            filters["start_time"] = now - deltas[unit]

    # MITRE in raw query
    mitre = re.search(r"T\d{4}(?:\.\d{3})?", parsed.get("raw", ""), re.I)
    if mitre:
        filters["mitre_technique"] = mitre.group(0).upper()
        filters["_force_alerts"] = True

    return filters


def score_event_details(event: dict[str, Any]) -> dict[str, Any]:
    """Score event and return breakdown for API."""
    scorer = get_anomaly_scorer()
    score = scorer.score_event(event)
    source_ip = event.get("source_ip", "unknown")
    baseline = scorer.get_baseline(source_ip)
    return {
        "anomaly_score": score,
        "risk_percent": round(score * 100, 1),
        "is_anomalous": score >= 0.6,
        "level": (
            "critical" if score >= 0.85
            else "high" if score >= 0.6
            else "medium" if score >= 0.35
            else "low"
        ),
        "baseline": baseline,
        "source_ip": source_ip,
    }
