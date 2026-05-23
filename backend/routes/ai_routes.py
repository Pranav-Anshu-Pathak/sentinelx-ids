"""AI / LLM API — copilot, anomaly scoring, NLP search, LLM analysis."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ai_engine.copilot import ATTACK_EXPLANATIONS
from backend.ai_service import (
    alert_to_context,
    get_anomaly_scorer,
    get_copilot,
    get_llm_client,
    get_nlp_parser,
    parsed_nlp_to_search_filters,
    score_event_details,
)
from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, LogEntry, User
from backend.routes.search_routes import _execute_search, _search_alerts

router = APIRouter(prefix="/ai", tags=["AI & LLM"])


# ── Schemas ──────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4096)
    alert_id: Optional[int] = None


class ChatResponse(BaseModel):
    reply: str
    provider: str
    model: str = ""
    fallback_used: bool = False
    latency_ms: float = 0.0


class ExplainAttackRequest(BaseModel):
    attack_type: str = Field(..., min_length=1, max_length=128)


class ScoreEventRequest(BaseModel):
    raw_message: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    severity: Optional[str] = "info"
    event_type: Optional[str] = None
    timestamp: Optional[str] = None
    log_id: Optional[int] = None


class NLPSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=1024)


class AIStatusResponse(BaseModel):
    llm_provider: str
    llm_model: str
    is_local: bool
    rate_limit_remaining: int
    modules: dict[str, bool]
    attack_types: list[str]


class RemediationResponse(BaseModel):
    alert_id: int
    steps: list[str]


# ── Endpoints ────────────────────────────────────────────────────────────

@router.get("/status", response_model=AIStatusResponse)
async def ai_status(current_user: User = Depends(get_current_user)) -> AIStatusResponse:
    """AI module status and configured LLM provider."""
    llm = get_llm_client()
    return AIStatusResponse(
        llm_provider=llm.provider,
        llm_model=llm._default_model(),
        is_local=llm.is_local,
        rate_limit_remaining=llm.rate_limit_remaining,
        modules={
            "copilot": True,
            "llm_integration": True,
            "anomaly_scorer": True,
            "nlp_query": True,
        },
        attack_types=sorted(ATTACK_EXPLANATIONS.keys()),
    )


@router.post("/chat", response_model=ChatResponse)
async def ai_chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChatResponse:
    """Chat with SOC assistant (LLM if configured, else local copilot)."""
    context: dict[str, Any] = {
        "username": current_user.username,
        "role": current_user.role.value,
    }
    if body.alert_id:
        alert = await db.get(Alert, body.alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        context["alert"] = alert_to_context(alert)

    llm = get_llm_client()
    resp = llm.get_response(body.message, context)
    return ChatResponse(
        reply=resp.content,
        provider=resp.provider,
        model=resp.model,
        fallback_used=resp.fallback_used or llm.is_local,
        latency_ms=resp.latency_ms,
    )


@router.post("/analyze-alert/{alert_id}")
async def analyze_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Full incident analysis for an alert (LLM + copilot)."""
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    ctx = alert_to_context(alert)
    llm = get_llm_client()
    prompt = (
        f"Analyze this security alert and provide incident summary, "
        f"MITRE mapping, impact, and recommended actions:\n{alert.title}"
    )
    analysis = llm.get_response(prompt, {"alert": ctx})
    local_summary = get_copilot().analyze_alert(ctx)

    return {
        "alert_id": alert_id,
        "analysis": analysis.content,
        "local_analysis": local_summary,
        "provider": analysis.provider,
        "model": analysis.model,
        "fallback_used": analysis.fallback_used,
    }


@router.post("/explain-attack")
async def explain_attack(
    body: ExplainAttackRequest,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Explain an attack type (MITRE + tactics)."""
    text = get_copilot().explain_attack(body.attack_type)
    return {"attack_type": body.attack_type, "explanation": text}


@router.post("/remediate/{alert_id}", response_model=RemediationResponse)
async def remediate_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationResponse:
    """Prioritized remediation steps for an alert."""
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    steps = get_copilot().recommend_remediation(alert_to_context(alert))
    return RemediationResponse(alert_id=alert_id, steps=steps)


@router.post("/score-event")
async def score_event(
    body: ScoreEventRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Anomaly score for a log event (0–1 scale + baseline)."""
    event: dict[str, Any] = {
        "raw_message": body.raw_message or "",
        "source_ip": body.source_ip,
        "dest_ip": body.dest_ip,
        "hostname": body.hostname,
        "severity": body.severity or "info",
        "event_type": body.event_type,
        "timestamp": body.timestamp,
    }

    if body.log_id:
        log = await db.get(LogEntry, body.log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")
        event = {
            "raw_message": log.raw_message,
            "source_ip": log.source_ip,
            "dest_ip": log.dest_ip,
            "hostname": log.hostname,
            "severity": log.severity.value,
            "event_type": log.event_type,
            "timestamp": log.timestamp.isoformat(),
            "message": log.raw_message,
        }

    details = score_event_details(event)
    if body.log_id:
        details["log_id"] = body.log_id
    return details


@router.post("/score-alert/{alert_id}")
async def score_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Anomaly score derived from alert fields."""
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    event = {
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "hostname": alert.hostname,
        "severity": alert.severity.value,
        "message": alert.description or alert.title,
        "event_type": alert.mitre_technique,
        "timestamp": alert.created_at.isoformat(),
    }
    details = score_event_details(event)
    details["alert_id"] = alert_id
    details["rule_risk_score"] = alert.risk_score
    return details


@router.post("/nlp-search")
async def nlp_search_ai(
    body: NLPSearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Natural language search using NLPQueryParser + DB execution."""
    parsed = get_nlp_parser().parse_query(body.query)
    filters = parsed_nlp_to_search_filters(parsed)

    force_alerts = filters.pop("_force_alerts", False) or parsed.get("type") == "alerts"
    if force_alerts:
        results, total, search_type = await _search_alerts(filters, db)
    else:
        results, total, search_type = await _execute_search(filters, db)

    return {
        "original_query": body.query,
        "parsed": parsed,
        "interpreted_query": f"{parsed.get('type', 'search')} → {search_type}",
        "filters_applied": filters,
        "results": results,
        "total": total,
        "search_type": search_type,
    }


@router.get("/baselines")
async def anomaly_baselines(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Rolling anomaly baselines per source IP."""
    return get_anomaly_scorer().get_all_baselines()
