"""SentinelX IDS - Syslog Parser.

Parses standard BSD-style syslog lines (RFC 3164) commonly found in Linux
``/var/log/auth.log``, ``/var/log/syslog``, and ``/var/log/messages``.

Recognised format::

    Mon DD HH:MM:SS hostname service[pid]: message

Also handles the variant without a PID::

    Mon DD HH:MM:SS hostname service: message
"""

from __future__ import annotations

import re
from datetime import datetime

from parsers.base_parser import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

# Main syslog line pattern (BSD / RFC 3164)
_SYSLOG_RE: re.Pattern[str] = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w\-/.]+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.+)$"
)

# Auth-specific sub-patterns for event typing
_AUTH_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    # (compiled pattern, event_type, severity)
    (
        re.compile(r"Failed password for invalid user (\S+) from ([\d.]+) port (\d+)"),
        "auth_failure_invalid_user",
        "high",
    ),
    (
        re.compile(r"Failed password for (\S+) from ([\d.]+) port (\d+)"),
        "auth_failure",
        "high",
    ),
    (
        re.compile(r"Accepted (password|publickey) for (\S+) from ([\d.]+) port (\d+)"),
        "auth_success",
        "info",
    ),
    (
        re.compile(r"Invalid user (\S+) from ([\d.]+)"),
        "invalid_user",
        "medium",
    ),
    (
        re.compile(r"pam_unix\(\S+:auth\): authentication failure.*rhost=([\d.]+)(?:\s+user=(\S+))?"),
        "pam_auth_failure",
        "high",
    ),
    (
        re.compile(r"error: maximum authentication attempts exceeded for (\S+) from ([\d.]+)"),
        "max_auth_exceeded",
        "critical",
    ),
    (
        re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)"),
        "sudo_command",
        "medium",
    ),
    (
        re.compile(r"sudo:.*authentication failure"),
        "sudo_auth_failure",
        "high",
    ),
    (
        re.compile(r"session opened for user (\S+)"),
        "session_open",
        "info",
    ),
    (
        re.compile(r"session closed for user (\S+)"),
        "session_close",
        "info",
    ),
    (
        re.compile(r"Disconnected from (\S+) port (\d+)"),
        "disconnect",
        "info",
    ),
    (
        re.compile(r"Connection closed by (\S+)"),
        "connection_closed",
        "info",
    ),
    (
        re.compile(r"Did not receive identification string from ([\d.]+)"),
        "no_ident",
        "medium",
    ),
    (
        re.compile(r"Connection reset by ([\d.]+)"),
        "connection_reset",
        "low",
    ),
    (
        re.compile(r"Received disconnect from ([\d.]+)"),
        "received_disconnect",
        "info",
    ),
    (
        re.compile(r"Accepted keyboard-interactive/pam for (\S+) from ([\d.]+) port (\d+)"),
        "auth_success",
        "info",
    ),
    (
        re.compile(r"user NOT in sudoers"),
        "sudoers_violation",
        "critical",
    ),
    (
        re.compile(r"COMMAND=.*/bin/(ba)?sh"),
        "shell_command",
        "medium",
    ),
]


class SyslogParser(BaseParser):
    """Parser for standard BSD / RFC 3164 syslog messages.

    Focuses heavily on authentication-related events found in
    ``/var/log/auth.log`` and provides rich metadata extraction for SSH,
    PAM, and sudo events.
    """

    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a single syslog line.

        Args:
            raw_line: Raw syslog log line.

        Returns:
            ``ParsedEvent`` on success, ``None`` if the line doesn't match.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        match = _SYSLOG_RE.match(raw_line)
        if not match:
            return None

        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        service = match.group("service")
        pid = match.group("pid") or ""
        message = match.group("message")

        # Parse timestamp (syslog format lacks year)
        timestamp = self.extract_timestamp(timestamp_str)

        # Extract IPs from message
        source_ip = self.extract_ip(message)
        all_ips = self.extract_all_ips(message)
        dest_ip = all_ips[1] if len(all_ips) > 1 else ""

        # Determine event type and severity from auth patterns
        event_type = "syslog"
        severity = "info"
        metadata: dict[str, object] = {}

        if pid:
            metadata["pid"] = pid

        for pattern, etype, sev in _AUTH_PATTERNS:
            auth_match = pattern.search(message)
            if auth_match:
                event_type = etype
                severity = sev
                groups = auth_match.groups()
                metadata["match_groups"] = groups

                # Extract username from known positions
                if etype in ("auth_failure", "auth_failure_invalid_user"):
                    metadata["username"] = groups[0]
                    if groups[1]:
                        source_ip = groups[1]
                elif etype == "auth_success":
                    metadata["auth_method"] = groups[0]
                    metadata["username"] = groups[1]
                    if groups[2]:
                        source_ip = groups[2]
                elif etype == "invalid_user":
                    metadata["username"] = groups[0]
                    if groups[1]:
                        source_ip = groups[1]
                elif etype == "pam_auth_failure":
                    if groups[0]:
                        source_ip = groups[0]
                    if len(groups) > 1 and groups[1]:
                        metadata["username"] = groups[1]
                elif etype == "max_auth_exceeded":
                    metadata["username"] = groups[0]
                    if groups[1]:
                        source_ip = groups[1]
                elif etype == "sudo_command":
                    metadata["sudo_user"] = groups[0]
                    metadata["sudo_command"] = groups[1]
                elif etype == "session_open" or etype == "session_close":
                    metadata["username"] = groups[0]
                break

        # If no auth pattern matched, use keyword-based severity
        if event_type == "syslog":
            severity = self.severity_from_keywords(message)

        return ParsedEvent(
            timestamp=timestamp,
            source="syslog",
            source_ip=source_ip,
            dest_ip=dest_ip,
            hostname=hostname,
            service=service,
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw_line,
            metadata=metadata,
        )
