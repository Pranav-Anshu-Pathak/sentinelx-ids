"""SentinelX IDS - Natural Language Query Parser.

Converts natural language queries from SOC analysts into structured
search/filter dictionaries that the backend API can execute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ParsedQuery:
    """Structured representation of a parsed natural-language query."""

    type: str  # search, alerts, aggregation, count, timeline
    filters: dict[str, str | int | list[str]] = field(default_factory=dict)
    field: str | None = None
    limit: int | None = None
    sort: str | None = None
    raw: str = ""

    def to_dict(self) -> dict:
        """Convert to a plain dictionary for JSON serialization."""
        result: dict = {"type": self.type, "filters": dict(self.filters)}
        if self.field is not None:
            result["field"] = self.field
        if self.limit is not None:
            result["limit"] = self.limit
        if self.sort is not None:
            result["sort"] = self.sort
        return result


# ---------------------------------------------------------------------------
# Time expression patterns
# ---------------------------------------------------------------------------

_TIME_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\blast\s+(\d+)\s*min(?:ute)?s?\b", re.IGNORECASE), "{n}m"),
    (re.compile(r"\blast\s+(\d+)\s*hours?\b", re.IGNORECASE), "{n}h"),
    (re.compile(r"\blast\s+(\d+)\s*days?\b", re.IGNORECASE), "{n}d"),
    (re.compile(r"\blast\s+(\d+)\s*weeks?\b", re.IGNORECASE), "{n}w"),
    (re.compile(r"\blast\s+hour\b", re.IGNORECASE), "1h"),
    (re.compile(r"\bpast\s+hour\b", re.IGNORECASE), "1h"),
    (re.compile(r"\blast\s+day\b", re.IGNORECASE), "24h"),
    (re.compile(r"\byesterday\b", re.IGNORECASE), "24h"),
    (re.compile(r"\btoday\b", re.IGNORECASE), "24h"),
    (re.compile(r"\bthis\s+week\b", re.IGNORECASE), "7d"),
    (re.compile(r"\blast\s+week\b", re.IGNORECASE), "7d"),
    (re.compile(r"\bthis\s+month\b", re.IGNORECASE), "30d"),
    (re.compile(r"\blast\s+month\b", re.IGNORECASE), "30d"),
    (re.compile(r"\blast\s+(\d+)\s*h\b", re.IGNORECASE), "{n}h"),
    (re.compile(r"\blast\s+(\d+)\s*m\b", re.IGNORECASE), "{n}m"),
    (re.compile(r"\blast\s+(\d+)\s*d\b", re.IGNORECASE), "{n}d"),
]

# ---------------------------------------------------------------------------
# Severity keywords
# ---------------------------------------------------------------------------

_SEVERITY_KEYWORDS: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}

# ---------------------------------------------------------------------------
# Query type patterns
# ---------------------------------------------------------------------------

_AGGREGATION_PATTERNS: list[tuple[re.Pattern[str], str, int | None]] = [
    (re.compile(r"top\s+(\d+)\s+(?:attacker\s+)?(?:source\s+)?ips?", re.IGNORECASE), "source_ip", None),
    (re.compile(r"top\s+(\d+)\s+(?:target\s+)?(?:destination\s+)?ips?", re.IGNORECASE), "destination_ip", None),
    (re.compile(r"top\s+(\d+)\s+(?:attacked\s+)?users?(?:names?)?", re.IGNORECASE), "username", None),
    (re.compile(r"top\s+(\d+)\s+(?:alert\s+)?(?:attack\s+)?types?", re.IGNORECASE), "attack_type", None),
    (re.compile(r"top\s+(\d+)\s+(?:source\s+)?(?:countries|country)", re.IGNORECASE), "country", None),
    (re.compile(r"most\s+(?:common|frequent)\s+(\w+)", re.IGNORECASE), None, 10),
]

_SEARCH_KEYWORDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"failed\s+(?:login|password|auth)", re.IGNORECASE), "failed"),
    (re.compile(r"successful\s+(?:login|auth)", re.IGNORECASE), "accepted"),
    (re.compile(r"brute\s*force", re.IGNORECASE), "brute_force"),
    (re.compile(r"reverse\s*shell", re.IGNORECASE), "reverse_shell"),
    (re.compile(r"port\s*scan", re.IGNORECASE), "port_scan"),
    (re.compile(r"privilege\s*escalat", re.IGNORECASE), "privilege_escalation"),
    (re.compile(r"lateral\s*move", re.IGNORECASE), "lateral_movement"),
    (re.compile(r"data\s*exfil", re.IGNORECASE), "data_exfiltration"),
    (re.compile(r"web\s*shell", re.IGNORECASE), "webshell"),
    (re.compile(r"power\s*shell", re.IGNORECASE), "powershell"),
    (re.compile(r"crypto\s*min", re.IGNORECASE), "cryptominer"),
    (re.compile(r"dns\s*tunnel", re.IGNORECASE), "dns_tunneling"),
    (re.compile(r"sql\s*inject", re.IGNORECASE), "sql_injection"),
    (re.compile(r"ssh", re.IGNORECASE), "ssh"),
    (re.compile(r"rdp", re.IGNORECASE), "rdp"),
    (re.compile(r"firewall", re.IGNORECASE), "firewall"),
]

# ---------------------------------------------------------------------------
# Entity extraction patterns
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

_HOSTNAME_PATTERN = re.compile(
    r"\b(?:host|server|machine|system)\s+([a-zA-Z][a-zA-Z0-9._-]{2,})\b",
    re.IGNORECASE,
)

_USERNAME_PATTERN = re.compile(
    r"\b(?:user|username|account)\s+([a-zA-Z][a-zA-Z0-9._-]{1,})\b",
    re.IGNORECASE,
)

_PORT_PATTERN = re.compile(
    r"\bport\s+(\d{1,5})\b", re.IGNORECASE
)


class NLPQueryParser:
    """Parses natural language SOC analyst queries into structured search filters.

    Supports time expressions, severity filtering, entity extraction (IPs,
    hostnames, usernames), aggregation queries, and keyword-based search.
    """

    def __init__(self) -> None:
        self._time_patterns = _TIME_PATTERNS
        self._severity_keywords = _SEVERITY_KEYWORDS
        self._aggregation_patterns = _AGGREGATION_PATTERNS
        self._search_keywords = _SEARCH_KEYWORDS

    def parse_query(self, natural_language: str) -> dict:
        """Convert a natural language query into a structured query dictionary.

        Args:
            natural_language: Free-text query from a SOC analyst.

        Returns:
            Structured query dictionary with type, filters, and optional
            field/limit/sort parameters.

        Examples:
            >>> parser = NLPQueryParser()
            >>> parser.parse_query("show failed logins from last hour")
            {'type': 'search', 'filters': {'message_contains': 'failed', 'time_range': '1h'}}
            >>> parser.parse_query("critical alerts today")
            {'type': 'alerts', 'filters': {'severity': 'critical', 'time_range': '24h'}}
            >>> parser.parse_query("top 10 attacker IPs")
            {'type': 'aggregation', 'filters': {}, 'field': 'source_ip', 'limit': 10}
        """
        text = natural_language.strip()
        parsed = ParsedQuery(type="search", raw=text)

        # 1. Extract time range
        time_range = self._extract_time_range(text)
        if time_range:
            parsed.filters["time_range"] = time_range

        # 2. Check for aggregation queries first
        agg_result = self._check_aggregation(text)
        if agg_result:
            parsed.type = "aggregation"
            parsed.field = agg_result[0]
            parsed.limit = agg_result[1]
            return parsed.to_dict()

        # 3. Check for count queries
        if self._is_count_query(text):
            parsed.type = "count"
            self._extract_search_filters(text, parsed)
            return parsed.to_dict()

        # 4. Check for timeline queries
        if self._is_timeline_query(text):
            parsed.type = "timeline"
            self._extract_search_filters(text, parsed)
            return parsed.to_dict()

        # 5. Check if it's an alerts query
        if self._is_alerts_query(text):
            parsed.type = "alerts"

        # 6. Extract severity
        severity = self._extract_severity(text)
        if severity:
            parsed.filters["severity"] = severity

        # 7. Extract entities
        entities = self._extract_entities(text)
        parsed.filters.update(entities)

        # 8. Extract search keywords
        self._extract_search_filters(text, parsed)

        return parsed.to_dict()

    # ------------------------------------------------------------------
    # Time Expression Parsing
    # ------------------------------------------------------------------

    def _extract_time_range(self, text: str) -> str | None:
        """Parse time expressions from the query text."""
        for pattern, template in self._time_patterns:
            match = pattern.search(text)
            if match:
                if match.groups():
                    n = match.group(1)
                    return template.format(n=n)
                return template
        return None

    # ------------------------------------------------------------------
    # Aggregation Detection
    # ------------------------------------------------------------------

    def _check_aggregation(self, text: str) -> tuple[str, int] | None:
        """Check if the query is an aggregation request."""
        for pattern, agg_field, default_limit in self._aggregation_patterns:
            match = pattern.search(text)
            if match:
                if match.groups():
                    limit = int(match.group(1))
                else:
                    limit = default_limit or 10

                resolved_field = agg_field
                if resolved_field is None:
                    # "most common X" — use X as the field
                    if len(match.groups()) >= 1:
                        resolved_field = match.group(1).lower()
                    else:
                        resolved_field = "source_ip"
                return (resolved_field, limit)
        return None

    # ------------------------------------------------------------------
    # Query Type Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_alerts_query(text: str) -> bool:
        """Determine if the query is specifically about alerts."""
        alert_keywords = re.compile(
            r"\balerts?\b|\bnotification|\bwarning|\bincident|\bthreat",
            re.IGNORECASE,
        )
        return bool(alert_keywords.search(text))

    @staticmethod
    def _is_count_query(text: str) -> bool:
        """Determine if the query is a count/statistics request."""
        count_keywords = re.compile(
            r"\bhow many\b|\bcount\b|\btotal\b|\bnumber of\b",
            re.IGNORECASE,
        )
        return bool(count_keywords.search(text))

    @staticmethod
    def _is_timeline_query(text: str) -> bool:
        """Determine if the query is a timeline/trend request."""
        timeline_keywords = re.compile(
            r"\btimeline\b|\btrend\b|\bover time\b|\bhistory\b|\bgraph\b|\bchart\b",
            re.IGNORECASE,
        )
        return bool(timeline_keywords.search(text))

    # ------------------------------------------------------------------
    # Severity Extraction
    # ------------------------------------------------------------------

    def _extract_severity(self, text: str) -> str | None:
        """Extract severity level from the query text."""
        words = re.findall(r"\b\w+\b", text.lower())
        for word in words:
            if word in self._severity_keywords:
                return self._severity_keywords[word]
        return None

    # ------------------------------------------------------------------
    # Entity Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entities(text: str) -> dict[str, str | list[str]]:
        """Extract IPs, hostnames, usernames, and ports from the query."""
        entities: dict[str, str | list[str]] = {}

        # Extract IP addresses
        ips = _IP_PATTERN.findall(text)
        if ips:
            valid_ips = [
                ip for ip in ips
                if all(0 <= int(octet) <= 255 for octet in ip.split("."))
            ]
            if len(valid_ips) == 1:
                entities["source_ip"] = valid_ips[0]
            elif valid_ips:
                entities["ip_addresses"] = valid_ips

        # Extract hostnames
        hostnames = _HOSTNAME_PATTERN.findall(text)
        if hostnames:
            entities["hostname"] = hostnames[0]

        # Extract usernames
        usernames = _USERNAME_PATTERN.findall(text)
        if usernames:
            entities["username"] = usernames[0]

        # Extract port numbers
        ports = _PORT_PATTERN.findall(text)
        if ports:
            entities["port"] = ports[0]

        return entities

    # ------------------------------------------------------------------
    # Search Keyword Extraction
    # ------------------------------------------------------------------

    def _extract_search_filters(self, text: str, parsed: ParsedQuery) -> None:
        """Extract search keywords and add them to filters."""
        matched_keywords: list[str] = []

        for pattern, keyword in self._search_keywords:
            if pattern.search(text):
                matched_keywords.append(keyword)

        if matched_keywords:
            if len(matched_keywords) == 1:
                parsed.filters["message_contains"] = matched_keywords[0]
            else:
                parsed.filters["message_contains"] = matched_keywords[0]
                parsed.filters["tags"] = matched_keywords

        # Sort extraction
        if re.search(r"\blatest|newest|recent|most recent\b", text, re.IGNORECASE):
            parsed.sort = "timestamp_desc"
        elif re.search(r"\boldest|earliest|first\b", text, re.IGNORECASE):
            parsed.sort = "timestamp_asc"
        if parsed.sort:
            parsed.filters["sort"] = parsed.sort

        # Limit extraction
        limit_match = re.search(r"\b(?:show|display|get|list)\s+(\d+)\b", text, re.IGNORECASE)
        if limit_match:
            parsed.limit = int(limit_match.group(1))
            parsed.filters["limit"] = parsed.limit
