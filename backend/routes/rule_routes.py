"""
SentinelX IDS - Detection Rule Routes

GET    /rules          – List all detection rules
POST   /rules          – Create a new rule
GET    /rules/{id}     – Single rule detail
PATCH  /rules/{id}     – Update / toggle a rule
DELETE /rules/{id}     – Delete a rule
"""

from __future__ import annotations

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user, require_role
from backend.database import get_db
from backend.models import Rule, Severity, User
from backend.schemas import RuleCreate, RuleResponse, RuleUpdate

router = APIRouter(prefix="/rules", tags=["Rules"])


@router.get(
    "",
    response_model=list[RuleResponse],
    summary="List detection rules",
)
async def list_rules(
    enabled_only: bool = Query(default=False, description="Return only enabled rules"),
    category: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RuleResponse]:
    """Return all detection rules, optionally filtered."""
    query = select(Rule)

    if enabled_only:
        query = query.where(Rule.enabled == True)  # noqa: E712
    if category:
        query = query.where(Rule.category == category)

    query = query.order_by(desc(Rule.created_at))
    result = await db.execute(query)
    rules = result.scalars().all()

    return [RuleResponse.model_validate(r) for r in rules]


@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a detection rule",
)
async def create_rule(
    rule_in: RuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> RuleResponse:
    """Create a new detection rule.

    If ``yaml_content`` is provided, the server parses it to extract
    name, description, severity, pattern, category, and MITRE mapping.
    Explicit fields take precedence over YAML-derived values.
    """
    # If YAML content is provided, try to extract fields from it
    yaml_data: dict = {}
    if rule_in.yaml_content:
        try:
            yaml_data = yaml.safe_load(rule_in.yaml_content) or {}
            if not isinstance(yaml_data, dict):
                yaml_data = {}
        except yaml.YAMLError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid YAML content in rule definition",
            )

    # Check for duplicate name
    existing = await db.execute(select(Rule).where(Rule.name == rule_in.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A rule named '{rule_in.name}' already exists",
        )

    rule = Rule(
        name=rule_in.name,
        description=rule_in.description or yaml_data.get("description"),
        category=rule_in.category or yaml_data.get("category"),
        mitre_technique=rule_in.mitre_technique or yaml_data.get("mitre_technique"),
        severity=Severity(rule_in.severity.value) if rule_in.severity else Severity.MEDIUM,
        pattern=rule_in.pattern or yaml_data.get("pattern") or yaml_data.get("detection", {}).get("pattern"),
        enabled=rule_in.enabled,
        yaml_content=rule_in.yaml_content,
    )
    db.add(rule)
    await db.flush()
    await db.refresh(rule)

    return RuleResponse.model_validate(rule)


@router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Get rule detail",
)
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RuleResponse:
    """Return a single detection rule by ID."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with id {rule_id} not found",
        )

    return RuleResponse.model_validate(rule)


@router.patch(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Update a rule",
)
async def update_rule(
    rule_id: int,
    update: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> RuleResponse:
    """Update a detection rule's fields (enable/disable, change pattern, etc.)."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with id {rule_id} not found",
        )

    if update.name is not None:
        # Check uniqueness
        dup = await db.execute(
            select(Rule).where(Rule.name == update.name, Rule.id != rule_id)
        )
        if dup.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A rule named '{update.name}' already exists",
            )
        rule.name = update.name
    if update.description is not None:
        rule.description = update.description
    if update.category is not None:
        rule.category = update.category
    if update.mitre_technique is not None:
        rule.mitre_technique = update.mitre_technique
    if update.severity is not None:
        rule.severity = Severity(update.severity.value)
    if update.pattern is not None:
        rule.pattern = update.pattern
    if update.enabled is not None:
        rule.enabled = update.enabled
    if update.yaml_content is not None:
        rule.yaml_content = update.yaml_content

    await db.flush()
    await db.refresh(rule)

    return RuleResponse.model_validate(rule)


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a rule",
)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
) -> None:
    """Permanently delete a detection rule."""
    result = await db.execute(select(Rule).where(Rule.id == rule_id))
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule with id {rule_id} not found",
        )

    await db.delete(rule)
    await db.flush()
