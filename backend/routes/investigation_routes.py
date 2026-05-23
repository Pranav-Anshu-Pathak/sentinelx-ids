"""Investigation CRUD endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_engine.copilot import SOCCopilot
from backend.auth import get_current_user
from backend.database import get_db
from backend.models import Alert, Investigation, InvestigationStatus, User
from backend.schemas import (
    InvestigationCreate,
    InvestigationResponse,
    InvestigationUpdate,
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])
_copilot = SOCCopilot()


@router.get("", response_model=list[InvestigationResponse])
async def list_investigations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[InvestigationResponse]:
    result = await db.execute(select(Investigation).order_by(desc(Investigation.created_at)))
    return [InvestigationResponse.model_validate(i) for i in result.scalars().all()]


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    body: InvestigationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    alert = await db.get(Alert, body.alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    ai_summary = None
    if body.notes:
        ai_summary = _copilot.analyze_alert(
            {
                "title": alert.title,
                "severity": alert.severity.value,
                "source_ip": alert.source_ip,
                "message": alert.description or alert.title,
                "mitre_technique": alert.mitre_technique,
            }
        )

    inv = Investigation(
        alert_id=body.alert_id,
        title=body.title,
        notes=body.notes,
        status=InvestigationStatus.OPEN,
        analyst=body.analyst or current_user.username,
        ai_summary=ai_summary,
    )
    db.add(inv)
    await db.flush()
    await db.refresh(inv)
    return InvestigationResponse.model_validate(inv)


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation_id: int,
    body: InvestigationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InvestigationResponse:
    inv = await db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if body.title is not None:
        inv.title = body.title
    if body.notes is not None:
        inv.notes = body.notes
    if body.status is not None:
        inv.status = InvestigationStatus(body.status.value)
    if body.analyst is not None:
        inv.analyst = body.analyst

    await db.flush()
    await db.refresh(inv)
    return InvestigationResponse.model_validate(inv)
