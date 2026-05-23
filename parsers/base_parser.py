"""SentinelX IDS - Base Parser Module.

Provides the abstract BaseParser class and the ParsedEvent dataclass that all
concrete log parsers must implement and produce. Includes common utility
methods for IP address extraction, timestamp parsing, and severity mapping.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class ParsedEvent:
    """Structured representation of a parsed log event.

    Attributes:
        timestamp: When the event occurred (UTC preferred).
        source: Originating log source identifier (e.g. 'syslog', 'windows_event').
        source_ip: Source IP address extracted from the log line, if available.
        dest_ip: Destination IP address, if available.
        hostname: Host that generated the log entry.
        service: Service or application name (e.g. 'sshd', 'httpd').
        message: Human-readable event message / the core log payload.
        severity: Normalised severity string — one of
                  'info', 'low', 'medium', 'high', 'critical'.
        event_type: Semantic event type (e.g. 'auth_failure', 'connection', 'alert').
        raw: The original, unmodified log line.
        metadata: Arbitrary key/value pairs for parser-specific extras.
    """

    timestamp: datetime
    source: str
    source_ip: str
    dest_ip: str
    hostname: str
    service: str
    message: str
    severity: str
    event_type: str
    raw: str
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pre-compiled patterns used by utility helpers
# ---------------------------------------------------------------------------

_IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IPV6_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:"
)

_SEVERITY_MAP: dict[str, str] = {
    # Direct mappings
    "emergency": "critical",
    "emerg": "critical",
    "alert": "critical",
    "critical": "critical",
    "crit": "critical",
    "error": "high",
    "err": "high",
    "warning": "medium",
    "warn": "medium",
    "notice": "low",
    "informational": "info",
    "info": "info",
    "debug": "info",
}

# Common timestamp formats tried in order
_TIMESTAMP_FORMATS: list[str] = [
    "%Y-%m-%dT%H:%M:%S.%fZ",         # ISO 8601 UTC
    "%Y-%m-%dT%H:%M:%SZ",             # ISO 8601 UTC (no micro)
    "%Y-%m-%dT%H:%M:%S.%f%z",         # ISO 8601 w/ tz
    "%Y-%m-%dT%H:%M:%S%z",            # ISO 8601 w/ tz (no micro)
    "%Y-%m-%dT%H:%M:%S.%f",           # ISO 8601 local
    "%Y-%m-%dT%H:%M:%S",              # ISO 8601 local (no micro)
    "%Y-%m-%d %H:%M:%S.%f",           # Common log timestamp
    "%Y-%m-%d %H:%M:%S",              # Common log timestamp (no micro)
    "%b %d %H:%M:%S",                 # Syslog (no year)
    "%d/%b/%Y:%H:%M:%S %z",           # Apache/Nginx CLF
    "%m/%d/%Y-%H:%M:%S.%f",           # Suricata fast.log
    "%m/%d/%Y %H:%M:%S",              # US date format
    "%d/%m/%Y %H:%M:%S",              # EU date format
]


class BaseParser(ABC):
    """Abstract base class for all log parsers.

    Subclasses **must** implement :meth:`parse` which converts a raw log line
    into a :class:`ParsedEvent` or returns ``None`` when the line cannot be
    understood by this parser.
    """

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a single raw log line into a structured event.

        Args:
            raw_line: A single line from a log file or stream.

        Returns:
            A ``ParsedEvent`` if the line is recognised, otherwise ``None``.
        """
        ...

    # ------------------------------------------------------------------
    # Utility helpers available to all subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def extract_ip(text: str) -> str:
        """Extract the first IPv4 address found in *text*.

        Falls back to attempting IPv6 extraction when no IPv4 is found.

        Args:
            text: Arbitrary string that may contain IP addresses.

        Returns:
            The first IP address string, or ``""`` if none is found.
        """
        match = _IPV4_PATTERN.search(text)
        if match:
            return match.group(0)
        match = _IPV6_PATTERN.search(text)
        if match:
            return match.group(0)
        return ""

    @staticmethod
    def extract_all_ips(text: str) -> list[str]:
        """Extract all IPv4 addresses found in *text*.

        Args:
            text: Arbitrary string.

        Returns:
            List of IPv4 address strings (may be empty).
        """
        return _IPV4_PATTERN.findall(text)

    @staticmethod
    def extract_timestamp(text: str) -> datetime:
        """Attempt to parse a timestamp string against known formats.

        Tries each format in :data:`_TIMESTAMP_FORMATS` in order and returns
        the first successful parse.  For syslog-style timestamps that lack a
        year component the current year is injected.

        Args:
            text: Raw timestamp string.

        Returns:
            A ``datetime`` instance.  Falls back to ``datetime.utcnow()`` if
            no format matches.
        """
        text = text.strip()
        for fmt in _TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(text, fmt)
                # Syslog format lacks year — pin to current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        # Last resort: return current time
        return datetime.utcnow()

    @staticmethod
    def normalize_severity(raw_severity: str) -> str:
        """Map a free-form severity string to one of the canonical levels.

        Canonical levels (in ascending order): ``info``, ``low``, ``medium``,
        ``high``, ``critical``.

        Args:
            raw_severity: Case-insensitive severity string (e.g. 'WARNING').

        Returns:
            Canonical severity string.
        """
        return _SEVERITY_MAP.get(raw_severity.strip().lower(), "info")

    @staticmethod
    def severity_from_keywords(message: str) -> str:
        """Infer severity from keywords found in *message*.

        A simple heuristic that scans for well-known keywords in the message
        body and maps them to severity levels.

        Args:
            message: Log message text.

        Returns:
            One of the canonical severity strings.
        """
        lower = message.lower()

        critical_kw = [
            "exploit", "rootkit", "backdoor", "reverse shell", "privilege escalation",
            "critical", "emergency", "panic", "breach",
        ]
        high_kw = [
            "error", "failed", "denied", "unauthorized", "forbidden",
            "attack", "malicious", "alert", "violation", "intrusion",
        ]
        medium_kw = [
            "warning", "warn", "suspect", "unusual", "anomal",
            "invalid", "bad", "reject",
        ]
        low_kw = [
            "notice", "accepted", "success", "info",
        ]

        for kw in critical_kw:
            if kw in lower:
                return "critical"
        for kw in high_kw:
            if kw in lower:
                return "high"
        for kw in medium_kw:
            if kw in lower:
                return "medium"
        for kw in low_kw:
            if kw in lower:
                return "low"
        return "info"
