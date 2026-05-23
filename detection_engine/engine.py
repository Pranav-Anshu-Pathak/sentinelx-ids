"""SentinelX IDS - Core Detection Engine.

Orchestrates the full detection pipeline:

1. Loads Sigma-like YAML rules via :class:`RuleLoader`.
2. For each incoming event, matches it against all enabled rules using
   pre-compiled regex patterns.
3. Calculates a ``risk_score`` combining rule severity and match count.
4. Returns a list of :class:`Alert` objects for events that trigger rules.

Thread-safe event counter exposed for metrics/monitoring.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from detection_engine.rule_loader import CompiledPattern, Rule, RuleLoader

logger = logging.getLogger("sentinelx.engine")

# ---------------------------------------------------------------------------
# Severity → numeric weight for risk scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: dict[str, float] = {
    "info": 0.1,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Alert:
    """An alert generated when an event matches a detection rule.

    Attributes:
        alert_id: Unique identifier for this alert instance.
        timestamp: When the alert was generated (UTC).
        rule_id: ID of the rule that triggered.
        rule_name: Human-readable name of the triggering rule.
        severity: Alert severity inherited from the rule.
        risk_score: Computed risk score (0.0 – 100.0).
        category: MITRE ATT&CK tactic / custom category.
        mitre_technique: MITRE technique ID.
        mitre_tactic: MITRE tactic name.
        source_ip: Source IP from the triggering event.
        dest_ip: Destination IP from the triggering event.
        hostname: Hostname from the triggering event.
        message: The event's message field.
        matched_patterns: List of regex patterns that matched.
        match_count: Number of patterns that matched.
        event: The original event dict.
        tags: Tags inherited from the rule.
    """

    alert_id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    severity: str
    risk_score: float
    category: str
    mitre_technique: str
    mitre_tactic: str
    source_ip: str
    dest_ip: str
    hostname: str
    message: str
    matched_patterns: list[str]
    match_count: int
    event: dict[str, Any]
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------


class DetectionEngine:
    """Core rule-based detection engine for SentinelX IDS.

    Usage::

        engine = DetectionEngine()
        engine.load_rules("./rules")
        alerts = await engine.process_event(event_dict)
    """

    def __init__(self) -> None:
        self._rule_loader = RuleLoader()
        self._rules: list[Rule] = []
        self._lock = asyncio.Lock()

        # Thread-safe event counter
        self._event_counter = _AtomicCounter()
        self._alert_counter = _AtomicCounter()
        self._start_time: float = time.time()

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def load_rules(self, rules_path: str) -> int:
        """Load detection rules from a directory.

        Args:
            rules_path: Path to the YAML rules directory.

        Returns:
            Number of rules loaded.
        """
        all_rules = self._rule_loader.load_rules_from_directory(rules_path)
        self._rules = [r for r in all_rules if r.enabled]
        logger.info("Detection engine loaded %d enabled rules", len(self._rules))
        return len(self._rules)

    def reload_rules(self) -> int:
        """Hot-reload rules from disk.

        Returns:
            Number of rules loaded after reload.
        """
        all_rules = self._rule_loader.reload_rules()
        self._rules = [r for r in all_rules if r.enabled]
        logger.info("Detection engine reloaded %d enabled rules", len(self._rules))
        return len(self._rules)

    @property
    def rule_loader(self) -> RuleLoader:
        """Access the underlying RuleLoader instance."""
        return self._rule_loader

    @property
    def rules(self) -> list[Rule]:
        """Return the list of currently active rules."""
        return list(self._rules)

    # ------------------------------------------------------------------
    # Event processing
    # ------------------------------------------------------------------

    async def process_event(self, event: dict[str, Any]) -> list[Alert]:
        """Process a single event against all enabled rules.

        The event dict is expected to contain some subset of::

            {
                "source_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "hostname": "web-01",
                "message": "Failed password for root from 10.0.0.1",
                "service": "sshd",
                "event_type": "auth_failure",
                "severity": "high",
                "timestamp": <datetime or epoch>,
                "source": "syslog",
                "metadata": {...}
            }

        Args:
            event: Structured event dictionary.

        Returns:
            List of ``Alert`` objects for every rule matched.
        """
        self._event_counter.increment()
        alerts: list[Alert] = []

        async with self._lock:
            for rule in self._rules:
                alert = self._match_rule(rule, event)
                if alert is not None:
                    alerts.append(alert)
                    self._alert_counter.increment()

        if alerts:
            logger.debug(
                "Event matched %d rule(s): %s",
                len(alerts),
                [a.rule_id for a in alerts],
            )

        return alerts

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @property
    def events_processed(self) -> int:
        """Total events processed since engine start."""
        return self._event_counter.value

    @property
    def alerts_generated(self) -> int:
        """Total alerts generated since engine start."""
        return self._alert_counter.value

    @property
    def uptime_seconds(self) -> float:
        """Seconds since engine was instantiated."""
        return time.time() - self._start_time

    def get_metrics(self) -> dict[str, Any]:
        """Return a snapshot of engine metrics."""
        uptime = self.uptime_seconds
        eps = self._event_counter.value / uptime if uptime > 0 else 0
        return {
            "events_processed": self._event_counter.value,
            "alerts_generated": self._alert_counter.value,
            "uptime_seconds": round(uptime, 2),
            "events_per_second": round(eps, 2),
            "rules_loaded": len(self._rules),
        }

    # ------------------------------------------------------------------
    # Internal matching logic
    # ------------------------------------------------------------------

    def _match_rule(self, rule: Rule, event: dict[str, Any]) -> Alert | None:
        """Test a single rule against an event.

        Returns an ``Alert`` if the rule's detection condition is satisfied.
        """
        if not rule.compiled_patterns:
            return None

        condition = rule.detection.get("condition", "any")
        matched_patterns: list[str] = []

        for cp in rule.compiled_patterns:
            field_value = self._resolve_field(event, cp.field_name)
            if not field_value:
                continue

            if cp.compiled.search(field_value):
                matched_patterns.append(cp.regex_source)

                # Short-circuit on first match for 'any' condition
                if condition == "any":
                    break

        # Evaluate condition
        match_count = len(matched_patterns)
        if condition == "any" and match_count == 0:
            return None
        if condition == "all" and match_count < len(rule.compiled_patterns):
            return None

        # Calculate risk score
        risk_score = self._calculate_risk_score(rule.severity, match_count, len(rule.compiled_patterns))

        return Alert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            risk_score=risk_score,
            category=rule.category,
            mitre_technique=rule.mitre_technique,
            mitre_tactic=rule.mitre_tactic,
            source_ip=str(event.get("source_ip", "")),
            dest_ip=str(event.get("dest_ip", "")),
            hostname=str(event.get("hostname", "")),
            message=str(event.get("message", "")),
            matched_patterns=matched_patterns,
            match_count=match_count,
            event=event,
            tags=list(rule.tags),
        )

    @staticmethod
    def _resolve_field(event: dict[str, Any], field_name: str) -> str:
        """Resolve a dotted field name from an event dict.

        Supports top-level keys and ``metadata.*`` sub-keys::

            "message"           → event["message"]
            "metadata.username" → event["metadata"]["username"]

        Args:
            event: The event dictionary.
            field_name: Dot-separated field path.

        Returns:
            The field value as a string, or ``""`` if not found.
        """
        if "." in field_name:
            parts = field_name.split(".", 1)
            sub = event.get(parts[0])
            if isinstance(sub, dict):
                return str(sub.get(parts[1], ""))
            return ""

        value = event.get(field_name, "")
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _calculate_risk_score(severity: str, match_count: int, total_patterns: int) -> float:
        """Compute a risk score on a 0–100 scale.

        Formula::

            base = severity_weight × 60
            match_bonus = (match_count / total_patterns) × 40
            risk = base + match_bonus

        Args:
            severity: Rule severity string.
            match_count: Number of patterns that matched.
            total_patterns: Total patterns in the rule.

        Returns:
            Risk score clamped to [0.0, 100.0].
        """
        weight = _SEVERITY_WEIGHTS.get(severity, 0.1)
        base = weight * 60.0
        ratio = match_count / max(total_patterns, 1)
        bonus = ratio * 40.0
        return min(100.0, round(base + bonus, 2))


# ---------------------------------------------------------------------------
# Thread-safe counter
# ---------------------------------------------------------------------------


class _AtomicCounter:
    """Simple thread-safe counter using a threading.Lock."""

    def __init__(self) -> None:
        self._value: int = 0
        self._lock = threading.Lock()

    def increment(self, amount: int = 1) -> int:
        """Atomically increment and return the new value."""
        with self._lock:
            self._value += amount
            return self._value

    @property
    def value(self) -> int:
        """Read the current value (atomic on most platforms for int reads)."""
        return self._value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self._value = 0
