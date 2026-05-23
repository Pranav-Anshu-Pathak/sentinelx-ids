"""SOC Copilot routes (alias for /ai/chat)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user
from backend.database import get_db
from backend.models import User
from backend.routes.ai_routes import ChatRequest, ChatResponse, ai_chat

router = APIRouter(prefix="/copilot", tags=["Copilot"])


class CopilotChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4096)
    alert_id: Optional[int] = None


@router.post("/chat", response_model=ChatResponse, summary="Chat with SOC Copilot")
async def copilot_chat(
    body: CopilotChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChatResponse:
    """Alias for POST /ai/chat."""
    return await ai_chat(
        body=ChatRequest(message=body.message, alert_id=body.alert_id),
        db=db,
        current_user=current_user,
    )
