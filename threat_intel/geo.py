"""
SentinelX IDS - GeoIP Enrichment

Uses the free ip-api.com API (no key required, 45 req/min) to enrich
IP addresses with geolocation, ASN, and ISP data.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_BATCH_ENDPOINT = "http://ip-api.com/batch"
_SINGLE_ENDPOINT = "http://ip-api.com/json/{ip}"
_FIELDS = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
_RATE_LIMIT = 45          # requests per minute (free tier)
_BATCH_SIZE = 100         # max IPs per batch request


@dataclass
class GeoInfo:
    """Geo-IP result for a single IP address."""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    success: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "asn_name": self.asn_name,
            "success": self.success,
        }


def _parse_geo_response(data: dict) -> GeoInfo:
    """Parse a single ip-api.com response dict."""
    ip = data.get("query", "")
    if data.get("status") != "success":
        return GeoInfo(ip=ip, success=False, error=data.get("message", "failed"))

    return GeoInfo(
        ip=ip,
        country=data.get("country"),
        country_code=data.get("countryCode"),
        region=data.get("regionName"),
        city=data.get("city"),
        latitude=data.get("lat"),
        longitude=data.get("lon"),
        timezone=data.get("timezone"),
        isp=data.get("isp"),
        org=data.get("org"),
        asn=data.get("as"),
        asn_name=data.get("asname"),
        success=True,
    )


async def lookup_single(ip: str, timeout: float = 5.0) -> GeoInfo:
    """Look up geo information for a single IP."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                _SINGLE_ENDPOINT.format(ip=ip),
                params={"fields": _FIELDS},
            )
            resp.raise_for_status()
            return _parse_geo_response(resp.json())
    except httpx.RequestError as exc:
        logger.warning("GeoIP lookup failed for %s: %s", ip, exc)
        return GeoInfo(ip=ip, success=False, error=str(exc))
    except Exception as exc:
        logger.warning("GeoIP unexpected error for %s: %s", ip, exc)
        return GeoInfo(ip=ip, success=False, error=str(exc))


async def lookup_batch(ips: list[str], timeout: float = 10.0) -> list[GeoInfo]:
    """Look up geo information for multiple IPs in batches."""
    if not ips:
        return []

    results: list[GeoInfo] = []
    unique_ips = list(dict.fromkeys(ips))  # deduplicate, preserve order

    for i in range(0, len(unique_ips), _BATCH_SIZE):
        chunk = unique_ips[i : i + _BATCH_SIZE]
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    _BATCH_ENDPOINT,
                    json=[{"query": ip, "fields": _FIELDS} for ip in chunk],
                )
                resp.raise_for_status()
                for item in resp.json():
                    results.append(_parse_geo_response(item))
        except httpx.RequestError as exc:
            logger.warning("GeoIP batch lookup failed: %s", exc)
            results.extend(GeoInfo(ip=ip, success=False, error=str(exc)) for ip in chunk)

        # Respect rate limit between batch chunks
        if i + _BATCH_SIZE < len(unique_ips):
            await asyncio.sleep(1.5)

    return results


# High-risk country codes (used in scoring)
HIGH_RISK_COUNTRY_CODES = {
    "CN", "RU", "KP", "IR", "SY", "CU", "SD",  # sanctioned / APT-heavy
    "NG", "RO", "BY", "UA",                       # high cybercrime volume
}


def geo_risk_modifier(geo: GeoInfo) -> float:
    """
    Return an additive risk modifier (0-15) based on geolocation.
    This is combined with other scores, not used alone for blocking.
    """
    if not geo.success or not geo.country_code:
        return 0.0
    if geo.country_code in HIGH_RISK_COUNTRY_CODES:
        return 15.0
    return 0.0
