"""
SentinelX IDS - Threat Feed Manager

Ingests free, open-source threat intelligence feeds and upserts them
into the local ThreatIntelEntry table.

Supported feeds:
  • Feodo Tracker  – botnet C2 IPs (CSV)
  • Emerging Threats – known bad IPs (text)
  • URLhaus          – malicious URLs/domains (CSV)
  • CINS Score       – scored bad-actor IPs (text)
  • ThreatFox        – multi-type IOCs (JSON API)
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Feed definitions
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FeedRecord:
    """Normalised IOC record from any feed."""
    indicator_type: str        # ip | domain | hash
    indicator_value: str
    threat_score: float
    threat_type: str
    source: str
    country: Optional[str] = None
    isp: Optional[str] = None
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedStatus:
    """Status of a single feed."""
    name: str
    url: str
    description: str
    enabled: bool = True
    last_sync: Optional[datetime] = None
    last_count: int = 0
    last_error: Optional[str] = None
    total_imported: int = 0


# Global feed registry
FEEDS: dict[str, FeedStatus] = {
    "feodo_tracker": FeedStatus(
        name="Feodo Tracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
        description="Botnet C2 IP blocklist from abuse.ch",
    ),
    "emerging_threats": FeedStatus(
        name="Emerging Threats",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        description="Compromised IP addresses from Emerging Threats",
    ),
    "cins_score": FeedStatus(
        name="CINS Army",
        url="http://cinsscore.com/list/ci-badguys.txt",
        description="Bad-actor IPs from CINS Score",
    ),
    "urlhaus": FeedStatus(
        name="URLhaus",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        description="Recent malicious URLs from abuse.ch URLhaus",
    ),
    "threatfox": FeedStatus(
        name="ThreatFox",
        url="https://threatfox-api.abuse.ch/api/v1/",
        description="Multi-type IOCs from abuse.ch ThreatFox",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Feed parsers
# ─────────────────────────────────────────────────────────────────────────────

async def _parse_feodo(content: str) -> AsyncIterator[FeedRecord]:
    """Parse Feodo Tracker CSV. Format: first_seen,dst_ip,dst_port,c2_status,last_online,malware."""
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 2:
            continue
        ip = row[1].strip()
        if not ip or ip == "dst_ip":
            continue
        malware = row[5].strip() if len(row) > 5 else "botnet"
        yield FeedRecord(
            indicator_type="ip",
            indicator_value=ip,
            threat_score=90.0,
            threat_type="botnet",
            source="feodo_tracker",
            tags={"malware_family": malware, "c2": True},
        )


async def _parse_plain_ip_list(content: str, source: str, threat_type: str, score: float) -> AsyncIterator[FeedRecord]:
    """Parse a plain-text file with one IP per line (# comments allowed)."""
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Some lists use CIDR; skip those for now
        if "/" in line:
            continue
        yield FeedRecord(
            indicator_type="ip",
            indicator_value=line,
            threat_score=score,
            threat_type=threat_type,
            source=source,
        )


async def _parse_urlhaus(content: str) -> AsyncIterator[FeedRecord]:
    """Parse URLhaus CSV for malicious URLs/domains."""
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 6:
            continue
        url = row[2].strip()
        if not url or url == "url":
            continue
        # Extract domain from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.hostname
            if not domain:
                continue
        except Exception:
            continue

        threat = row[5].strip() or "malware"
        tags_raw = row[6].strip() if len(row) > 6 else ""
        tags = {"url": url}
        if tags_raw:
            tags["tags"] = tags_raw

        yield FeedRecord(
            indicator_type="domain",
            indicator_value=domain,
            threat_score=80.0,
            threat_type="malware",
            source="urlhaus",
            tags=tags,
        )


async def _parse_threatfox(data: dict) -> AsyncIterator[FeedRecord]:
    """Parse ThreatFox JSON API response."""
    iocs = data.get("data", [])
    if not isinstance(iocs, list):
        return

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "")
        value = ioc.get("ioc", "").strip()
        if not value:
            continue

        # Map ThreatFox types to ours
        if ioc_type in ("ip:port",):
            # Strip port if present
            indicator_type = "ip"
            value = value.split(":")[0]
        elif ioc_type in ("domain", "url"):
            indicator_type = "domain"
            if ioc_type == "url":
                try:
                    from urllib.parse import urlparse
                    value = urlparse(value).hostname or value
                except Exception:
                    continue
        elif ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
            indicator_type = "hash"
        else:
            continue

        confidence = ioc.get("confidence_level", 50)
        threat_score = min(100.0, float(confidence))
        malware = ioc.get("malware", "unknown")
        threat_type_raw = ioc.get("threat_type", "malware")

        yield FeedRecord(
            indicator_type=indicator_type,
            indicator_value=value,
            threat_score=threat_score,
            threat_type=threat_type_raw or "malware",
            source="threatfox",
            tags={
                "malware_family": malware,
                "confidence_level": confidence,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main sync engine
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """Fetch URL content with error handling."""
    try:
        resp = await client.get(url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
        return resp.text
    except Exception as exc:
        logger.error("Feed fetch failed for %s: %s", url, exc)
        return None


async def sync_feed(feed_key: str, db: AsyncSession) -> int:
    """
    Sync a single threat feed into the database.
    Returns the number of records upserted.
    """
    from backend.models import IndicatorType, ThreatIntelEntry

    status = FEEDS.get(feed_key)
    if not status or not status.enabled:
        return 0

    logger.info("Syncing feed: %s", status.name)
    imported = 0

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": "SentinelX-IDS/1.0 ThreatIntelSync"},
            timeout=30.0,
        ) as client:
            records: list[FeedRecord] = []

            if feed_key == "feodo_tracker":
                content = await _fetch(client, status.url)
                if content:
                    records = [r async for r in _parse_feodo(content)]

            elif feed_key == "emerging_threats":
                content = await _fetch(client, status.url)
                if content:
                    records = [
                        r async for r in _parse_plain_ip_list(
                            content, "emerging_threats", "scanner", 70.0
                        )
                    ]

            elif feed_key == "cins_score":
                content = await _fetch(client, status.url)
                if content:
                    records = [
                        r async for r in _parse_plain_ip_list(
                            content, "cins_army", "scanner", 65.0
                        )
                    ]

            elif feed_key == "urlhaus":
                content = await _fetch(client, status.url)
                if content:
                    records = [r async for r in _parse_urlhaus(content)]

            elif feed_key == "threatfox":
                # Query last 7 days
                resp = await client.post(
                    status.url,
                    json={"query": "get_iocs", "days": 7},
                    headers={"API-KEY": ""},
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    records = [r async for r in _parse_threatfox(resp.json())]

            # Upsert records into DB (in batches of 200)
            BATCH = 200
            for i in range(0, len(records), BATCH):
                chunk = records[i : i + BATCH]
                for rec in chunk:
                    try:
                        it = IndicatorType(rec.indicator_type)
                    except ValueError:
                        continue

                    # Check for existing
                    result = await db.execute(
                        select(ThreatIntelEntry).where(
                            ThreatIntelEntry.indicator_type == it,
                            ThreatIntelEntry.indicator_value == rec.indicator_value,
                        )
                    )
                    existing = result.scalar_one_or_none()

                    now = datetime.now(timezone.utc)
                    if existing:
                        # Only update if new score is higher
                        if rec.threat_score > existing.threat_score:
                            existing.threat_score = rec.threat_score
                            existing.threat_type = rec.threat_type
                        existing.last_seen = now
                        merged_tags = {**(existing.tags or {}), **rec.tags}
                        existing.tags = merged_tags
                    else:
                        entry = ThreatIntelEntry(
                            indicator_type=it,
                            indicator_value=rec.indicator_value,
                            threat_score=rec.threat_score,
                            threat_type=rec.threat_type,
                            source=rec.source,
                            country=rec.country,
                            isp=rec.isp,
                            tags=rec.tags,
                            first_seen=now,
                            last_seen=now,
                        )
                        db.add(entry)
                        imported += 1

                await db.flush()

        status.last_sync = datetime.now(timezone.utc)
        status.last_count = len(records)
        status.total_imported += imported
        status.last_error = None
        logger.info("Feed %s synced: %d new records", status.name, imported)

    except Exception as exc:
        status.last_error = str(exc)
        logger.error("Feed sync error for %s: %s", feed_key, exc)

    return imported


async def sync_all_feeds(db: AsyncSession) -> dict[str, int]:
    """Sync all enabled feeds. Returns per-feed import counts."""
    results = {}
    for feed_key in FEEDS:
        count = await sync_feed(feed_key, db)
        results[feed_key] = count
        # Small delay between feeds to be polite
        await asyncio.sleep(0.5)
    return results


def get_feed_statuses() -> list[dict]:
    """Return current status of all feeds as dicts."""
    out = []
    for key, status in FEEDS.items():
        out.append({
            "id": key,
            "name": status.name,
            "url": status.url,
            "description": status.description,
            "enabled": status.enabled,
            "last_sync": status.last_sync.isoformat() if status.last_sync else None,
            "last_count": status.last_count,
            "last_error": status.last_error,
            "total_imported": status.total_imported,
            "status": "error" if status.last_error else ("synced" if status.last_sync else "pending"),
        })
    return out
