"""
SentinelX IDS - Threat Intelligence Engine

High-level orchestrator that coordinates:
  - Local IOC database lookups
  - External API enrichment (AbuseIPDB, VirusTotal)
  - GeoIP enrichment
  - Threat scoring / verdict

This is the primary entry point for the threat intel subsystem.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.models import IndicatorType, ThreatIntelEntry
from threat_intel.geo import GeoInfo, lookup_single
from threat_intel.scorer import ThreatVerdict, score_domain, score_hash, score_ip

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# External API helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _abuseipdb_check(ip: str) -> dict[str, Any]:
    """Query AbuseIPDB v2 check endpoint."""
    if not settings.ABUSEIPDB_API_KEY:
        return {"source": "abuseipdb", "available": False}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "source": "abuseipdb",
                    "available": True,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "usage_type": data.get("usageType"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported_at": data.get("lastReportedAt"),
                }
            return {"source": "abuseipdb", "available": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"source": "abuseipdb", "available": False, "error": str(exc)}


async def _virustotal_ip(ip: str) -> dict[str, Any]:
    """Query VirusTotal v3 for IP address analysis."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "available": False}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "available": True,
                    "as_owner": attrs.get("as_owner"),
                    "country": attrs.get("country"),
                    "reputation": attrs.get("reputation", 0),
                    "malicious_detections": stats.get("malicious", 0),
                    "suspicious_detections": stats.get("suspicious", 0),
                    "harmless_detections": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_votes": attrs.get("total_votes", {}),
                }
            return {"source": "virustotal", "available": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"source": "virustotal", "available": False, "error": str(exc)}


async def _virustotal_domain(domain: str) -> dict[str, Any]:
    """Query VirusTotal v3 for domain analysis."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "available": False}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "available": True,
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                    "reputation": attrs.get("reputation", 0),
                    "malicious_detections": stats.get("malicious", 0),
                    "suspicious_detections": stats.get("suspicious", 0),
                    "harmless_detections": stats.get("harmless", 0),
                }
            return {"source": "virustotal", "available": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"source": "virustotal", "available": False, "error": str(exc)}


async def _virustotal_hash(file_hash: str) -> dict[str, Any]:
    """Query VirusTotal v3 for file hash analysis."""
    if not settings.VIRUSTOTAL_API_KEY:
        return {"source": "virustotal", "available": False}

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal",
                    "available": True,
                    "type_description": attrs.get("type_description"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "malicious_detections": stats.get("malicious", 0),
                    "suspicious_detections": stats.get("suspicious", 0),
                    "harmless_detections": stats.get("harmless", 0),
                    "size": attrs.get("size"),
                    "first_submission_date": attrs.get("first_submission_date"),
                }
            elif resp.status_code == 404:
                return {"source": "virustotal", "available": True, "not_found": True,
                        "malicious_detections": 0, "suspicious_detections": 0}
            return {"source": "virustotal", "available": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"source": "virustotal", "available": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# Local DB helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _get_local_entries(
    db: AsyncSession, indicator_type: IndicatorType, value: str
) -> list[ThreatIntelEntry]:
    result = await db.execute(
        select(ThreatIntelEntry).where(
            ThreatIntelEntry.indicator_type == indicator_type,
            ThreatIntelEntry.indicator_value == value,
        )
    )
    return result.scalars().all()


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def enrich_ip(ip: str, db: AsyncSession) -> ThreatVerdict:
    """
    Full IP enrichment pipeline:
    1. Local DB lookup
    2. GeoIP
    3. AbuseIPDB
    4. VirusTotal
    5. Score and return verdict
    """
    local_entries = await _get_local_entries(db, IndicatorType.IP, ip)
    local_score = max((e.threat_score for e in local_entries), default=0.0)
    local_tags = {}
    local_type = None
    for entry in local_entries:
        local_tags.update(entry.tags or {})
        if entry.threat_type:
            local_type = entry.threat_type

    # Run geo + external lookups in parallel
    geo_task = lookup_single(ip)
    abuse_task = _abuseipdb_check(ip)
    vt_task = _virustotal_ip(ip)

    import asyncio
    geo, abuse_data, vt_data = await asyncio.gather(geo_task, abuse_task, vt_task)

    return score_ip(
        ip=ip,
        local_score=local_score,
        local_tags=local_tags,
        local_threat_type=local_type,
        abuseipdb_data=abuse_data,
        virustotal_data=vt_data,
        geo=geo,
    )


async def enrich_domain(domain: str, db: AsyncSession) -> ThreatVerdict:
    """Full domain enrichment pipeline."""
    local_entries = await _get_local_entries(db, IndicatorType.DOMAIN, domain)
    local_score = max((e.threat_score for e in local_entries), default=0.0)
    local_tags = {}
    local_type = None
    for entry in local_entries:
        local_tags.update(entry.tags or {})
        if entry.threat_type:
            local_type = entry.threat_type

    vt_data = await _virustotal_domain(domain)

    return score_domain(
        domain=domain,
        local_score=local_score,
        local_tags=local_tags,
        local_threat_type=local_type,
        virustotal_data=vt_data,
    )


async def enrich_hash(file_hash: str, db: AsyncSession) -> ThreatVerdict:
    """Full file hash enrichment pipeline."""
    local_entries = await _get_local_entries(db, IndicatorType.HASH, file_hash)
    local_score = max((e.threat_score for e in local_entries), default=0.0)
    local_tags = {}
    local_type = None
    for entry in local_entries:
        local_tags.update(entry.tags or {})
        if entry.threat_type:
            local_type = entry.threat_type

    vt_data = await _virustotal_hash(file_hash)

    return score_hash(
        file_hash=file_hash,
        local_score=local_score,
        local_tags=local_tags,
        local_threat_type=local_type,
        virustotal_data=vt_data,
    )


async def get_intel_stats(db: AsyncSession) -> dict[str, Any]:
    """Return aggregate statistics about the threat intel database."""
    from sqlalchemy import func as sqlfunc

    # Total count by type
    result = await db.execute(
        select(
            ThreatIntelEntry.indicator_type,
            sqlfunc.count(ThreatIntelEntry.id).label("count"),
            sqlfunc.avg(ThreatIntelEntry.threat_score).label("avg_score"),
            sqlfunc.max(ThreatIntelEntry.threat_score).label("max_score"),
        ).group_by(ThreatIntelEntry.indicator_type)
    )
    by_type = {}
    total = 0
    for row in result:
        by_type[row.indicator_type.value] = {
            "count": row.count,
            "avg_score": round(float(row.avg_score or 0), 1),
            "max_score": round(float(row.max_score or 0), 1),
        }
        total += row.count

    # Critical/high count
    critical_result = await db.execute(
        select(sqlfunc.count(ThreatIntelEntry.id)).where(
            ThreatIntelEntry.threat_score >= 85
        )
    )
    critical_count = critical_result.scalar() or 0

    high_result = await db.execute(
        select(sqlfunc.count(ThreatIntelEntry.id)).where(
            ThreatIntelEntry.threat_score >= 65,
            ThreatIntelEntry.threat_score < 85,
        )
    )
    high_count = high_result.scalar() or 0

    # Top sources
    source_result = await db.execute(
        select(
            ThreatIntelEntry.source,
            sqlfunc.count(ThreatIntelEntry.id).label("count"),
        )
        .where(ThreatIntelEntry.source.isnot(None))
        .group_by(ThreatIntelEntry.source)
        .order_by(desc("count"))
        .limit(10)
    )
    top_sources = [{"source": row.source, "count": row.count} for row in source_result]

    # Top threat types
    type_result = await db.execute(
        select(
            ThreatIntelEntry.threat_type,
            sqlfunc.count(ThreatIntelEntry.id).label("count"),
        )
        .where(ThreatIntelEntry.threat_type.isnot(None))
        .group_by(ThreatIntelEntry.threat_type)
        .order_by(desc("count"))
        .limit(10)
    )
    top_types = [{"threat_type": row.threat_type, "count": row.count} for row in type_result]

    # Recent additions (last 24h)
    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_result = await db.execute(
        select(sqlfunc.count(ThreatIntelEntry.id)).where(
            ThreatIntelEntry.first_seen >= cutoff
        )
    )
    recent_24h = recent_result.scalar() or 0

    return {
        "total": total,
        "by_type": by_type,
        "critical_count": critical_count,
        "high_count": high_count,
        "top_sources": top_sources,
        "top_threat_types": top_types,
        "recent_24h": recent_24h,
    }
