"""
SentinelX IDS - Threat Intelligence Routes

Endpoints:
  GET  /intel/stats            – Aggregate IOC statistics
  GET  /intel/lookup/{ip}      – Full IP enrichment (local + external + geo)
  POST /intel/enrich           – Enrich any indicator (IP, domain, hash)
  GET  /intel/iocs             – List / search IOC entries
  POST /intel/iocs             – Add new IOC
  GET  /intel/iocs/{id}        – Get single IOC by ID
  PATCH /intel/iocs/{id}       – Update IOC
  DELETE /intel/iocs/{id}      – Delete IOC (admin)
  POST /intel/block            – Block IP (high-threat IOC)
  GET  /intel/geo/{ip}         – Raw GeoIP lookup
  GET  /intel/feeds/status     – Feed sync status
  POST /intel/feeds/sync       – Trigger feed sync (admin/analyst)
  POST /intel/feeds/sync/{key} – Sync a specific feed
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.auth import get_current_user, require_role
from backend.config import settings
from backend.database import get_db
from backend.models import IndicatorType, ThreatIntelEntry, User
from backend.schemas import (
    IPLookupRequest,
    ThreatIntelCreate,
    ThreatIntelResponse,
)
from backend.audit import audit
from backend.models import AuditAction
from fastapi import Request
from threat_intel.engine import enrich_domain, enrich_hash, enrich_ip, get_intel_stats
from threat_intel.feeds import FEEDS, get_feed_statuses, sync_all_feeds, sync_feed
from threat_intel.geo import lookup_single

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


# ─────────────────────────────────────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/stats", summary="Aggregate IOC statistics")
async def intel_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return aggregate statistics about the threat intel database."""
    return await get_intel_stats(db)


# ─────────────────────────────────────────────────────────────────────────────
# Lookup & Enrichment
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/lookup/{ip}", summary="Full IP reputation lookup")
async def ip_lookup(
    ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Full IP enrichment: local DB + GeoIP + AbuseIPDB + VirusTotal.
    Returns a detailed ThreatVerdict with all component scores.
    """
    verdict = await enrich_ip(ip.strip(), db)
    return verdict.to_dict()


@router.post("/enrich", summary="Enrich any indicator (IP, domain, or hash)")
async def enrich_indicator(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Enrich any IOC type.
    Body: { "indicator_type": "ip"|"domain"|"hash", "value": "..." }
    """
    itype = body.get("indicator_type", "ip").lower()
    value = (body.get("value") or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="'value' is required")

    if itype == "ip":
        verdict = await enrich_ip(value, db)
    elif itype == "domain":
        verdict = await enrich_domain(value, db)
    elif itype == "hash":
        verdict = await enrich_hash(value, db)
    else:
        raise HTTPException(status_code=400, detail="indicator_type must be ip, domain, or hash")

    return verdict.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# IOC CRUD
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/iocs",
    response_model=list[ThreatIntelResponse],
    summary="List / search IOC entries",
)
async def list_iocs(
    indicator_type: Optional[str] = Query(default=None, description="Filter by type: ip, domain, hash"),
    min_score: float = Query(default=0.0, ge=0, le=100, description="Minimum threat score"),
    search: Optional[str] = Query(default=None, description="Full-text search on indicator value"),
    threat_type: Optional[str] = Query(default=None, description="Filter by threat type"),
    source: Optional[str] = Query(default=None, description="Filter by feed source"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    sort_by: str = Query(default="threat_score", description="Sort field: threat_score | last_seen | first_seen"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatIntelResponse]:
    """Return IOC entries from the local threat intel database with filtering and search."""
    query = select(ThreatIntelEntry).where(ThreatIntelEntry.threat_score >= min_score)

    if indicator_type:
        try:
            it = IndicatorType(indicator_type.lower())
            query = query.where(ThreatIntelEntry.indicator_type == it)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid indicator_type: {indicator_type}")

    if search:
        query = query.where(ThreatIntelEntry.indicator_value.ilike(f"%{search}%"))

    if threat_type:
        query = query.where(ThreatIntelEntry.threat_type == threat_type)

    if source:
        query = query.where(ThreatIntelEntry.source == source)

    # Sorting
    sort_col = {
        "threat_score": ThreatIntelEntry.threat_score,
        "last_seen": ThreatIntelEntry.last_seen,
        "first_seen": ThreatIntelEntry.first_seen,
    }.get(sort_by, ThreatIntelEntry.threat_score)

    query = query.order_by(desc(sort_col)).offset(offset).limit(limit)
    result = await db.execute(query)
    entries = result.scalars().all()
    return [ThreatIntelResponse.model_validate(e) for e in entries]


@router.get(
    "/iocs/{ioc_id}",
    response_model=ThreatIntelResponse,
    summary="Get single IOC by ID",
)
async def get_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatIntelResponse:
    result = await db.execute(select(ThreatIntelEntry).where(ThreatIntelEntry.id == ioc_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ThreatIntelResponse.model_validate(entry)


@router.post(
    "/iocs",
    response_model=ThreatIntelResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add new IOC",
)
async def add_ioc(
    ioc_in: ThreatIntelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> ThreatIntelResponse:
    """Add a new Indicator of Compromise. Updates score/tags if indicator already exists."""
    result = await db.execute(
        select(ThreatIntelEntry).where(
            ThreatIntelEntry.indicator_type == IndicatorType(ioc_in.indicator_type.value),
            ThreatIntelEntry.indicator_value == ioc_in.indicator_value,
        )
    )
    existing = result.scalar_one_or_none()

    if existing is not None:
        existing.threat_score = max(existing.threat_score, ioc_in.threat_score)
        existing.last_seen = datetime.now(timezone.utc)
        if ioc_in.threat_type:
            existing.threat_type = ioc_in.threat_type
        if ioc_in.source:
            existing.source = ioc_in.source
        if ioc_in.country:
            existing.country = ioc_in.country
        if ioc_in.isp:
            existing.isp = ioc_in.isp
        if ioc_in.tags:
            merged = {**(existing.tags or {}), **ioc_in.tags}
            existing.tags = merged
        await db.flush()
        await db.refresh(existing)
        return ThreatIntelResponse.model_validate(existing)

    entry = ThreatIntelEntry(
        indicator_type=IndicatorType(ioc_in.indicator_type.value),
        indicator_value=ioc_in.indicator_value,
        threat_score=ioc_in.threat_score,
        threat_type=ioc_in.threat_type,
        source=ioc_in.source or "manual",
        country=ioc_in.country,
        isp=ioc_in.isp,
        tags={**(ioc_in.tags or {}), "added_by": current_user.username},
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    return ThreatIntelResponse.model_validate(entry)


@router.patch(
    "/iocs/{ioc_id}",
    response_model=ThreatIntelResponse,
    summary="Update IOC",
)
async def update_ioc(
    ioc_id: int,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> ThreatIntelResponse:
    """Update specific fields of an existing IOC."""
    result = await db.execute(select(ThreatIntelEntry).where(ThreatIntelEntry.id == ioc_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IOC not found")

    if "threat_score" in body:
        entry.threat_score = float(body["threat_score"])
    if "threat_type" in body:
        entry.threat_type = body["threat_type"]
    if "source" in body:
        entry.source = body["source"]
    if "country" in body:
        entry.country = body["country"]
    if "isp" in body:
        entry.isp = body["isp"]
    if "tags" in body and isinstance(body["tags"], dict):
        entry.tags = {**(entry.tags or {}), **body["tags"]}

    entry.last_seen = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(entry)
    return ThreatIntelResponse.model_validate(entry)


@router.delete(
    "/iocs/{ioc_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete IOC",
)
async def delete_ioc(
    ioc_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
) -> None:
    """Delete an IOC from the threat intel database (admin only)."""
    result = await db.execute(select(ThreatIntelEntry).where(ThreatIntelEntry.id == ioc_id))
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="IOC not found")
    val = entry.indicator_value
    await db.delete(entry)
    await db.flush()
    await audit(db, current_user, AuditAction.IOC_DELETE,
                resource_type="ioc", resource_id=val,
                description=f"Deleted IOC '{val}' (id={ioc_id})",
                request=request)


# ─────────────────────────────────────────────────────────────────────────────
# Block IP
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/block", summary="Block IP (record as high-threat IOC)")
async def block_ip(
    body: IPLookupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Mark an IP as blocked by adding/updating a threat intel IOC with score 99."""
    ip = body.ip.strip()
    result = await db.execute(
        select(ThreatIntelEntry).where(
            ThreatIntelEntry.indicator_type == IndicatorType.IP,
            ThreatIntelEntry.indicator_value == ip,
        )
    )
    entry = result.scalar_one_or_none()
    if entry:
        entry.threat_score = 99.0
        entry.threat_type = "blocked"
        entry.last_seen = datetime.now(timezone.utc)
        tags = {**(entry.tags or {}), "blocked": True, "blocked_by": current_user.username}
        entry.tags = tags
    else:
        entry = ThreatIntelEntry(
            indicator_type=IndicatorType.IP,
            indicator_value=ip,
            threat_score=99.0,
            threat_type="blocked",
            source="sentinelx_manual",
            tags={"blocked": True, "blocked_by": current_user.username},
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(entry)
    await db.flush()
    await audit(db, current_user, AuditAction.IP_BLOCK,
                resource_type="ioc", resource_id=ip,
                description=f"Blocked IP {ip}",
                request=request)
    return {"status": "blocked", "ip": ip, "threat_score": 99.0, "blocked_by": current_user.username}


@router.post("/unblock", summary="Unblock IP")
async def unblock_ip(
    body: IPLookupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Remove block from an IP."""
    ip = body.ip.strip()
    result = await db.execute(
        select(ThreatIntelEntry).where(
            ThreatIntelEntry.indicator_type == IndicatorType.IP,
            ThreatIntelEntry.indicator_value == ip,
            ThreatIntelEntry.threat_type == "blocked",
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="No blocked entry found for this IP")

    entry.threat_type = "unknown"
    entry.threat_score = max(0.0, entry.threat_score - 40.0)
    tags = {k: v for k, v in (entry.tags or {}).items() if k not in ("blocked", "blocked_by")}
    tags["unblocked_by"] = current_user.username
    entry.tags = tags
    entry.last_seen = datetime.now(timezone.utc)
    await db.flush()
    await audit(db, current_user, AuditAction.IP_UNBLOCK,
                resource_type="ioc", resource_id=ip,
                description=f"Unblocked IP {ip}",
                request=request)
    return {"status": "unblocked", "ip": ip}


# ─────────────────────────────────────────────────────────────────────────────
# GeoIP
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/geo/{ip}", summary="GeoIP lookup for an IP address")
async def geo_lookup(
    ip: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return geolocation information for an IP address using ip-api.com (free, no key needed)."""
    geo = await lookup_single(ip.strip())
    return geo.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Feed Management
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/feeds/status", summary="Threat feed sync status")
async def feed_status(
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return current status of all configured threat intelligence feeds."""
    return get_feed_statuses()


@router.post("/feeds/sync", summary="Sync all threat feeds")
async def sync_feeds(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Trigger a background sync of all enabled threat intelligence feeds."""
    # Run in background so the endpoint returns immediately
    background_tasks.add_task(_run_sync_all, db)
    return {
        "status": "sync_started",
        "feeds": list(FEEDS.keys()),
        "message": "Feed sync running in background. Check /intel/feeds/status for progress.",
    }


@router.post("/feeds/sync/{feed_key}", summary="Sync a specific threat feed")
async def sync_single_feed(
    feed_key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
) -> dict:
    """Trigger immediate sync of a specific feed (blocks until complete)."""
    if feed_key not in FEEDS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown feed: {feed_key}. Valid: {list(FEEDS.keys())}",
        )
    imported = await sync_feed(feed_key, db)
    return {
        "status": "synced",
        "feed": feed_key,
        "imported": imported,
        "feed_status": get_feed_statuses(),
    }


async def _run_sync_all(db: AsyncSession) -> None:
    """Background task wrapper for full feed sync."""
    try:
        await sync_all_feeds(db)
        await db.commit()
    except Exception as exc:
        logger.error("Background feed sync failed: %s", exc)
        await db.rollback()


import logging
logger = logging.getLogger(__name__)
