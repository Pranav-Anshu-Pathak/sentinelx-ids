"""SentinelX IDS - Web Server Log Parser.

Parses Apache Combined Log Format and Nginx access logs::

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Example::

    192.168.1.100 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1"
    200 2326 "http://example.com" "Mozilla/5.0 ..."

Includes real-time detection of:
- SQL injection attempts
- Cross-site scripting (XSS)
- Path traversal attacks
- Suspicious user agents (scanners, bots, exploit tools)
- Abnormally large response sizes
"""

from __future__ import annotations

import re
from datetime import datetime

from parsers.base_parser import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

# Apache / Nginx Combined Log Format
_COMBINED_LOG_RE: re.Pattern[str] = re.compile(
    r'^(?P<client_ip>[\d.]+)\s+'           # %h
    r'(?P<ident>\S+)\s+'                    # %l
    r'(?P<user>\S+)\s+'                     # %u
    r'\[(?P<timestamp>[^\]]+)\]\s+'         # %t
    r'"(?P<method>[A-Z]+)\s+'               # Request method
    r'(?P<path>\S+)\s+'                     # Request path
    r'(?P<protocol>\S+)"\s+'                # Protocol
    r'(?P<status>\d{3})\s+'                 # %>s
    r'(?P<bytes>\d+|-)\s*'                  # %b
    r'(?:"(?P<referer>[^"]*)"\s*)?'         # Referer (optional)
    r'(?:"(?P<user_agent>[^"]*)")?'         # User-Agent (optional)
)

# SQL injection patterns
_SQLI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:union\s+(?:all\s+)?select)", re.IGNORECASE),
    re.compile(r"(?i)(?:select\s+.*\s+from\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:insert\s+into\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:update\s+\S+\s+set\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:delete\s+from\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:drop\s+(?:table|database)\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:or\s+1\s*=\s*1)", re.IGNORECASE),
    re.compile(r"(?i)(?:or\s+'[^']*'\s*=\s*'[^']*')", re.IGNORECASE),
    re.compile(r"(?i)(?:and\s+1\s*=\s*1)", re.IGNORECASE),
    re.compile(r"(?i)(?:'\s*(?:or|and|--|#))", re.IGNORECASE),
    re.compile(r"(?i)(?:;\s*(?:drop|delete|insert|update|exec|execute))", re.IGNORECASE),
    re.compile(r"(?i)(?:waitfor\s+delay\s+)", re.IGNORECASE),
    re.compile(r"(?i)(?:benchmark\s*\()", re.IGNORECASE),
    re.compile(r"(?i)(?:sleep\s*\(\d+\))", re.IGNORECASE),
    re.compile(r"(?:0x[0-9a-fA-F]{8,})", re.IGNORECASE),
    re.compile(r"(?i)(?:information_schema)", re.IGNORECASE),
    re.compile(r"(?i)(?:load_file\s*\()", re.IGNORECASE),
    re.compile(r"(?i)(?:into\s+(?:out|dump)file)", re.IGNORECASE),
]

# XSS patterns
_XSS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)<script[^>]*>", re.IGNORECASE),
    re.compile(r"(?i)javascript\s*:", re.IGNORECASE),
    re.compile(r"(?i)on(?:error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"(?i)eval\s*\(", re.IGNORECASE),
    re.compile(r"(?i)document\.(?:cookie|location|write)", re.IGNORECASE),
    re.compile(r"(?i)alert\s*\(", re.IGNORECASE),
    re.compile(r"(?i)<img[^>]+onerror\s*=", re.IGNORECASE),
    re.compile(r"(?i)<iframe", re.IGNORECASE),
    re.compile(r"(?i)<svg[^>]+onload\s*=", re.IGNORECASE),
    re.compile(r"(?i)String\.fromCharCode", re.IGNORECASE),
    re.compile(r"%3[Cc]script", re.IGNORECASE),
]

# Path traversal patterns
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:\.\./){2,}"),
    re.compile(r"(?:%2[Ee]){2}%2[Ff]"),
    re.compile(r"(?:\.\.\\){2,}"),
    re.compile(r"/etc/(?:passwd|shadow|hosts|sudoers)"),
    re.compile(r"(?i)/proc/self/"),
    re.compile(r"(?i)/windows/system32/"),
    re.compile(r"(?i)(?:c|d):\\\\"),
    re.compile(r"(?i)/var/log/"),
    re.compile(r"%00"),  # Null byte injection
    re.compile(r"(?i)/boot\.ini"),
    re.compile(r"(?i)/wp-config\.php"),
    re.compile(r"(?i)/\.env"),
]

# Suspicious user agents
_SUSPICIOUS_UA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)nikto", re.IGNORECASE),
    re.compile(r"(?i)sqlmap", re.IGNORECASE),
    re.compile(r"(?i)nmap", re.IGNORECASE),
    re.compile(r"(?i)masscan", re.IGNORECASE),
    re.compile(r"(?i)dirbuster", re.IGNORECASE),
    re.compile(r"(?i)gobuster", re.IGNORECASE),
    re.compile(r"(?i)burpsuite", re.IGNORECASE),
    re.compile(r"(?i)hydra", re.IGNORECASE),
    re.compile(r"(?i)wfuzz", re.IGNORECASE),
    re.compile(r"(?i)(?:python-requests|python-urllib|curl/|wget/|libwww-perl)", re.IGNORECASE),
    re.compile(r"(?i)metasploit", re.IGNORECASE),
    re.compile(r"(?i)(?:zgrab|censys|shodan)", re.IGNORECASE),
    re.compile(r"(?i)havij", re.IGNORECASE),
    re.compile(r"(?i)acunetix", re.IGNORECASE),
    re.compile(r"(?i)openvas", re.IGNORECASE),
    re.compile(r"(?i)nessus", re.IGNORECASE),
    re.compile(r"^$"),  # Empty user agent
    re.compile(r"^-$"),  # Dash user agent
]

# Threshold for "large response" in bytes
_LARGE_RESPONSE_THRESHOLD: int = 10_000_000  # 10 MB


class WebServerParser(BaseParser):
    """Parser for Apache / Nginx Combined Log Format access logs.

    Performs real-time attack signature detection against request paths,
    query strings, referrers, and user agent strings.
    """

    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a single web access log line.

        Args:
            raw_line: Raw access log line in Combined Log Format.

        Returns:
            ``ParsedEvent`` on success, ``None`` if the line doesn't match.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        match = _COMBINED_LOG_RE.match(raw_line)
        if not match:
            return None

        client_ip = match.group("client_ip")
        ident = match.group("ident")
        user = match.group("user")
        timestamp_str = match.group("timestamp")
        method = match.group("method")
        path = match.group("path")
        protocol = match.group("protocol")
        status_str = match.group("status")
        bytes_str = match.group("bytes")
        referer = match.group("referer") or ""
        user_agent = match.group("user_agent") or ""

        # Parse timestamp (Apache CLF: 10/Oct/2024:13:55:36 -0700)
        timestamp = self.extract_timestamp(timestamp_str)

        # Parse numeric fields
        status_code = int(status_str)
        bytes_sent = int(bytes_str) if bytes_str not in ("-", "") else 0

        # Detect attacks
        attacks: list[str] = []
        severity = "info"

        # SQL injection
        full_request = f"{path} {referer}"
        for pattern in _SQLI_PATTERNS:
            if pattern.search(full_request):
                attacks.append("sqli")
                severity = "critical"
                break

        # XSS
        for pattern in _XSS_PATTERNS:
            if pattern.search(full_request):
                attacks.append("xss")
                if severity != "critical":
                    severity = "high"
                break

        # Path traversal
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path):
                attacks.append("path_traversal")
                if severity not in ("critical", "high"):
                    severity = "high"
                break

        # Suspicious user agent
        for pattern in _SUSPICIOUS_UA_PATTERNS:
            if pattern.search(user_agent):
                attacks.append("suspicious_ua")
                if severity not in ("critical", "high"):
                    severity = "medium"
                break

        # Large response
        if bytes_sent > _LARGE_RESPONSE_THRESHOLD:
            attacks.append("large_response")
            if severity not in ("critical", "high"):
                severity = "medium"

        # HTTP errors
        if 400 <= status_code < 500 and severity == "info":
            severity = "low"
        elif status_code >= 500 and severity == "info":
            severity = "medium"

        # Event type
        if attacks:
            event_type = f"web_attack_{'_'.join(attacks)}"
        elif status_code == 403:
            event_type = "web_forbidden"
        elif status_code == 404:
            event_type = "web_not_found"
        elif status_code >= 500:
            event_type = "web_server_error"
        else:
            event_type = "web_access"

        # Message
        message = f"{method} {path} -> {status_code} ({bytes_sent} bytes)"
        if attacks:
            message += f" [ATTACK: {', '.join(attacks)}]"

        metadata: dict[str, object] = {
            "method": method,
            "path": path,
            "protocol": protocol,
            "status_code": status_code,
            "bytes_sent": bytes_sent,
            "referer": referer,
            "user_agent": user_agent,
            "user": user if user != "-" else "",
            "ident": ident if ident != "-" else "",
            "attacks": attacks,
        }

        return ParsedEvent(
            timestamp=timestamp,
            source="web_access",
            source_ip=client_ip,
            dest_ip="",
            hostname="",
            service="httpd",
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw_line,
            metadata=metadata,
        )
