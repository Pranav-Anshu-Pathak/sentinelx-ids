"""Database seeding: demo user, YAML rules, sample threat intel."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from sqlalchemy import select

from backend.auth import seed_demo_user
from backend.database import async_session
from backend.models import IndicatorType, Rule, Severity, ThreatIntelEntry

logger = logging.getLogger("sentinelx.seed")

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _extract_pattern(yaml_data: dict) -> str | None:
    detection = yaml_data.get("detection") or {}
    patterns = detection.get("patterns") or []
    regexes: list[str] = []
    for p in patterns:
        if isinstance(p, dict) and p.get("regex"):
            regexes.append(p["regex"])
    if regexes:
        return regexes[0]
    return None


async def seed_rules_from_yaml() -> int:
    """Load YAML rules from disk into the database (idempotent)."""
    if not RULES_DIR.exists():
        logger.warning("Rules directory not found: %s", RULES_DIR)
        return 0

    count = 0
    async with async_session() as session:
        for yml_file in sorted(RULES_DIR.glob("*.yml")):
            with yml_file.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}

            name = data.get("name", yml_file.stem)
            existing = await session.execute(select(Rule).where(Rule.name == name))
            if existing.scalar_one_or_none():
                continue

            severity = _SEVERITY_MAP.get(
                str(data.get("severity", "medium")).lower(), Severity.MEDIUM
            )
            rule = Rule(
                name=name,
                description=data.get("description"),
                category=data.get("category"),
                mitre_technique=data.get("mitre_technique"),
                severity=severity,
                pattern=_extract_pattern(data),
                enabled=data.get("enabled", True),
                yaml_content=yml_file.read_text(encoding="utf-8"),
            )
            session.add(rule)
            count += 1

        await session.commit()
    logger.info("Seeded %d detection rules from YAML", count)
    return count


async def seed_demo_intel() -> None:
    """Insert sample IOCs for threat intel UI."""
    samples = [
        ("203.0.113.42", IndicatorType.IP, 85.0, "brute_force", "internal", "CN"),
        ("185.220.101.1", IndicatorType.IP, 92.0, "tor_exit", "abuseipdb", "DE"),
        ("malware-c2.evil.com", IndicatorType.DOMAIN, 95.0, "c2", "virustotal", None),
    ]
    async with async_session() as session:
        for value, itype, score, threat_type, source, country in samples:
            existing = await session.execute(
                select(ThreatIntelEntry).where(ThreatIntelEntry.indicator_value == value)
            )
            if existing.scalar_one_or_none():
                continue
            session.add(
                ThreatIntelEntry(
                    indicator_type=itype,
                    indicator_value=value,
                    threat_score=score,
                    threat_type=threat_type,
                    source=source,
                    country=country,
                )
            )
        await session.commit()


async def seed_all() -> None:
    """Run all seed routines."""
    await seed_demo_user()
    await seed_rules_from_yaml()
    await seed_demo_intel()
