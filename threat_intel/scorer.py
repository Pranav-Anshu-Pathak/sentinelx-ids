"""
SentinelX IDS - Threat Scorer

Combines signals from multiple sources to produce a final threat score
and classification for any IOC (IP, domain, or hash).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from threat_intel.geo import GeoInfo, geo_risk_modifier

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Threat type classification labels
# ─────────────────────────────────────────────────────────────────────────────

THREAT_TYPES = {
    "botnet":              "Botnet / C2",
    "scanner":             "Port Scanner",
    "tor_exit":            "Tor Exit Node",
    "malware":             "Malware Distribution",
    "phishing":            "Phishing",
    "spam":                "Spam Source",
    "brute_force":         "Brute Force",
    "data_exfiltration":   "Data Exfiltration",
    "cryptominer":         "Cryptominer",
    "proxy":               "Open Proxy / VPN",
    "blocked":             "Manually Blocked",
    "unknown":             "Unknown Threat",
}

SEVERITY_THRESHOLDS = {
    "critical": 85,
    "high":     65,
    "medium":   40,
    "low":      15,
    "clean":    0,
}


@dataclass
class ThreatVerdict:
    """Final combined verdict for an IOC."""
    indicator: str
    indicator_type: str                     # ip | domain | hash
    final_score: float                      # 0-100
    severity: str                           # critical | high | medium | low | clean
    threat_type: str                        # botnet | scanner | ...
    threat_type_label: str                  # human-readable
    is_known_threat: bool
    confidence: float                       # 0-1

    # Component scores
    local_score: float = 0.0
    abuseipdb_score: float = 0.0
    virustotal_score: float = 0.0
    geo_risk_score: float = 0.0

    # Enrichment data
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    tags: dict[str, Any] = field(default_factory=dict)

    # Raw external data
    external: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "final_score": round(self.final_score, 1),
            "severity": self.severity,
            "threat_type": self.threat_type,
            "threat_type_label": self.threat_type_label,
            "is_known_threat": self.is_known_threat,
            "confidence": round(self.confidence, 2),
            "scores": {
                "local": round(self.local_score, 1),
                "abuseipdb": round(self.abuseipdb_score, 1),
                "virustotal": round(self.virustotal_score, 1),
                "geo_risk": round(self.geo_risk_score, 1),
            },
            "geo": {
                "country": self.country,
                "country_code": self.country_code,
                "city": self.city,
                "isp": self.isp,
                "asn": self.asn,
            },
            "tags": self.tags,
            "external": self.external,
        }


def _severity_from_score(score: float) -> str:
    for label, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return label
    return "clean"


def _infer_threat_type(
    tags: dict,
    abuseipdb_data: dict,
    vt_data: dict,
    existing_type: Optional[str] = None,
) -> str:
    """Infer threat type from available signals."""
    if existing_type and existing_type in THREAT_TYPES:
        return existing_type

    # Check tags
    tag_keys = {str(k).lower() for k in (tags or {}).keys()}
    if "blocked" in tag_keys:
        return "blocked"
    if "botnet" in tag_keys or "c2" in tag_keys:
        return "botnet"
    if "tor" in tag_keys:
        return "tor_exit"
    if "scanner" in tag_keys or "scan" in tag_keys:
        return "scanner"
    if "malware" in tag_keys:
        return "malware"
    if "phishing" in tag_keys:
        return "phishing"
    if "spam" in tag_keys:
        return "spam"

    # AbuseIPDB usage type hints
    usage = (abuseipdb_data.get("usage_type") or "").lower()
    if "tor" in usage:
        return "tor_exit"
    if "proxy" in usage or "vpn" in usage:
        return "proxy"
    if "data center" in usage or "hosting" in usage:
        return "scanner"  # common scanner origin

    return "unknown"


def score_ip(
    ip: str,
    local_score: float = 0.0,
    local_tags: Optional[dict] = None,
    local_threat_type: Optional[str] = None,
    abuseipdb_data: Optional[dict] = None,
    virustotal_data: Optional[dict] = None,
    geo: Optional[GeoInfo] = None,
) -> ThreatVerdict:
    """
    Compute a combined threat verdict for an IP address.

    Weights:
    - Local DB:        40%  (already verified by analysts)
    - AbuseIPDB:       35%  (community reports, 0-100 scale)
    - VirusTotal:      15%  (AV detections, normalised to 0-100)
    - Geo risk:        10%  (additive modifier)
    """
    abuseipdb_data = abuseipdb_data or {}
    virustotal_data = virustotal_data or {}
    local_tags = local_tags or {}

    # ── Component scores ─────────────────────────────────────────────────
    abuse_raw = float(abuseipdb_data.get("abuse_confidence_score") or 0)
    abuseipdb_score = abuse_raw  # already 0-100

    vt_malicious = int(virustotal_data.get("malicious_detections") or 0)
    vt_suspicious = int(virustotal_data.get("suspicious_detections") or 0)
    vt_total = vt_malicious + vt_suspicious
    # Scale: 1 detection = 10 pts, cap at 100
    virustotal_score = min(100.0, vt_total * 10.0)

    geo_score = geo_risk_modifier(geo) if geo else 0.0

    # ── Weighted final score ─────────────────────────────────────────────
    weighted = (
        local_score   * 0.40
        + abuseipdb_score * 0.35
        + virustotal_score * 0.15
        + geo_score       * 0.10
    )
    final_score = min(100.0, max(0.0, weighted))

    # If we have a verified local record, bias upward
    if local_score >= 70:
        final_score = max(final_score, local_score * 0.85)

    severity = _severity_from_score(final_score)
    threat_type = _infer_threat_type(local_tags, abuseipdb_data, virustotal_data, local_threat_type)

    # Confidence: how many sources agree
    sources_with_signal = sum([
        local_score > 0,
        abuseipdb_score > 20,
        virustotal_score > 0,
    ])
    confidence = min(1.0, sources_with_signal / 2.0)

    return ThreatVerdict(
        indicator=ip,
        indicator_type="ip",
        final_score=final_score,
        severity=severity,
        threat_type=threat_type,
        threat_type_label=THREAT_TYPES.get(threat_type, threat_type),
        is_known_threat=final_score >= 40 or local_score > 0,
        confidence=confidence,
        local_score=local_score,
        abuseipdb_score=abuseipdb_score,
        virustotal_score=virustotal_score,
        geo_risk_score=geo_score,
        country=geo.country if geo and geo.success else None,
        country_code=geo.country_code if geo and geo.success else None,
        city=geo.city if geo and geo.success else None,
        isp=geo.isp if geo and geo.success else None,
        asn=geo.asn if geo and geo.success else None,
        tags=local_tags,
        external={
            "abuseipdb": abuseipdb_data,
            "virustotal": virustotal_data,
        },
    )


def score_domain(
    domain: str,
    local_score: float = 0.0,
    local_tags: Optional[dict] = None,
    local_threat_type: Optional[str] = None,
    virustotal_data: Optional[dict] = None,
) -> ThreatVerdict:
    """Compute a combined threat verdict for a domain."""
    virustotal_data = virustotal_data or {}
    local_tags = local_tags or {}

    vt_malicious = int(virustotal_data.get("malicious_detections") or 0)
    virustotal_score = min(100.0, vt_malicious * 10.0)

    final_score = min(100.0, local_score * 0.60 + virustotal_score * 0.40)
    severity = _severity_from_score(final_score)
    threat_type = _infer_threat_type(local_tags, {}, virustotal_data, local_threat_type)

    return ThreatVerdict(
        indicator=domain,
        indicator_type="domain",
        final_score=final_score,
        severity=severity,
        threat_type=threat_type,
        threat_type_label=THREAT_TYPES.get(threat_type, threat_type),
        is_known_threat=final_score >= 40 or local_score > 0,
        confidence=min(1.0, (local_score > 0) * 0.5 + (virustotal_score > 0) * 0.5),
        local_score=local_score,
        virustotal_score=virustotal_score,
        tags=local_tags,
        external={"virustotal": virustotal_data},
    )


def score_hash(
    file_hash: str,
    local_score: float = 0.0,
    local_tags: Optional[dict] = None,
    local_threat_type: Optional[str] = None,
    virustotal_data: Optional[dict] = None,
) -> ThreatVerdict:
    """Compute a combined threat verdict for a file hash."""
    virustotal_data = virustotal_data or {}
    local_tags = local_tags or {}

    vt_malicious = int(virustotal_data.get("malicious_detections") or 0)
    virustotal_score = min(100.0, vt_malicious * 4.0)  # more detection weight for hashes

    final_score = min(100.0, local_score * 0.50 + virustotal_score * 0.50)
    severity = _severity_from_score(final_score)
    threat_type = _infer_threat_type(local_tags, {}, virustotal_data, local_threat_type) or "malware"

    return ThreatVerdict(
        indicator=file_hash,
        indicator_type="hash",
        final_score=final_score,
        severity=severity,
        threat_type=threat_type,
        threat_type_label=THREAT_TYPES.get(threat_type, threat_type),
        is_known_threat=final_score >= 40 or local_score > 0,
        confidence=min(1.0, (local_score > 0) * 0.5 + (virustotal_score > 0) * 0.5),
        local_score=local_score,
        virustotal_score=virustotal_score,
        tags=local_tags,
        external={"virustotal": virustotal_data},
    )
