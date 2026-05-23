"""SentinelX IDS - Firewall Log Parser.

Parses firewall log entries from:

1. **Linux iptables** — kernel log messages with key=value pairs::

       kernel: [12345.678] iptables: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8
       LEN=52 TOS=0x00 PREC=0x00 TTL=64 PROTO=TCP SPT=54321 DPT=22 ...

2. **Windows Firewall** — space-delimited log lines::

       2024-01-01 12:00:00 DROP TCP 1.2.3.4 5.6.7.8 54321 22 ...
"""

from __future__ import annotations

import re
from datetime import datetime

from parsers.base_parser import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns
# ---------------------------------------------------------------------------

# iptables log pattern
_IPTABLES_RE: re.Pattern[str] = re.compile(
    r"(?P<timestamp>\S+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"   # syslog timestamp
    r"(?P<hostname>\S+)\s+"                                  # hostname
    r"kernel:\s*\[?\s*[\d.]*\]?\s*"                          # kernel prefix
    r"(?P<prefix>iptables|netfilter|UFW\s\w+)?:?\s*"         # optional chain prefix
    r"(?P<kvpairs>.+)$"                                      # remaining key=value pairs
)

# Alternative iptables pattern (no syslog header, raw kernel log)
_IPTABLES_RAW_RE: re.Pattern[str] = re.compile(
    r"(?P<prefix>iptables|netfilter|UFW\s\w+)?:?\s*"
    r"(?=.*\bSRC=)(?P<kvpairs>.+)$"
)

# Windows Firewall log pattern
_WINFIREWALL_RE: re.Pattern[str] = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>ALLOW|DROP|INFO-EVENTS-LOST|OPEN|CLOSE)\s+"
    r"(?P<protocol>TCP|UDP|ICMP|\d+)\s+"
    r"(?P<src_ip>[\d.]+)\s+"
    r"(?P<dst_ip>[\d.]+)\s+"
    r"(?P<src_port>\d+|-)\s+"
    r"(?P<dst_port>\d+|-)\s*"
    r"(?P<rest>.*)?$"
)

# Key=Value extractor for iptables
_KV_RE: re.Pattern[str] = re.compile(r"(\w+)=(\S*)")

# High-risk destination ports
_HIGH_RISK_PORTS: frozenset[int] = frozenset({
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986,
    6379, 8080, 8443, 8888, 9200, 27017,
})


class FirewallParser(BaseParser):
    """Parser for iptables and Windows Firewall log formats.

    Automatically detects which format a given line belongs to and
    delegates to the appropriate internal parser.
    """

    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a single firewall log line.

        Args:
            raw_line: Raw log line from a firewall log file.

        Returns:
            ``ParsedEvent`` on success, ``None`` if the line is not recognised.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try Windows Firewall first (stricter format)
        event = self._parse_windows_firewall(raw_line)
        if event is not None:
            return event

        # Try iptables with syslog header
        event = self._parse_iptables(raw_line)
        if event is not None:
            return event

        # Try raw iptables (no syslog header)
        event = self._parse_iptables_raw(raw_line)
        return event

    # ------------------------------------------------------------------
    # iptables parser
    # ------------------------------------------------------------------

    def _parse_iptables(self, raw: str) -> ParsedEvent | None:
        """Parse iptables log with syslog header."""
        match = _IPTABLES_RE.match(raw)
        if not match:
            return None

        timestamp_str = match.group("timestamp")
        hostname = match.group("hostname")
        prefix = (match.group("prefix") or "").strip()
        kvpairs_str = match.group("kvpairs")

        return self._build_iptables_event(timestamp_str, hostname, prefix, kvpairs_str, raw)

    def _parse_iptables_raw(self, raw: str) -> ParsedEvent | None:
        """Parse raw iptables log line (no syslog header)."""
        match = _IPTABLES_RAW_RE.match(raw)
        if not match:
            return None

        prefix = (match.group("prefix") or "").strip()
        kvpairs_str = match.group("kvpairs")

        return self._build_iptables_event("", "", prefix, kvpairs_str, raw)

    def _build_iptables_event(
        self,
        timestamp_str: str,
        hostname: str,
        prefix: str,
        kvpairs_str: str,
        raw: str,
    ) -> ParsedEvent:
        """Build a ParsedEvent from iptables key=value data."""
        # Extract key-value pairs
        kv: dict[str, str] = dict(_KV_RE.findall(kvpairs_str))

        src_ip = kv.get("SRC", "")
        dst_ip = kv.get("DST", "")
        protocol = kv.get("PROTO", "")
        src_port = kv.get("SPT", "")
        dst_port = kv.get("DPT", "")
        in_iface = kv.get("IN", "")
        out_iface = kv.get("OUT", "")
        ttl = kv.get("TTL", "")
        length = kv.get("LEN", "")
        mac = kv.get("MAC", "")

        # Determine action from prefix
        action = "LOG"
        prefix_lower = prefix.lower()
        if "drop" in prefix_lower or "block" in prefix_lower:
            action = "DROP"
        elif "reject" in prefix_lower:
            action = "REJECT"
        elif "accept" in prefix_lower or "allow" in prefix_lower:
            action = "ACCEPT"

        # Timestamp
        timestamp = self.extract_timestamp(timestamp_str) if timestamp_str else datetime.utcnow()

        # Severity
        severity = self._compute_severity(action, dst_port, protocol)

        # Event type
        event_type = self._compute_event_type(action, protocol)

        # Message
        message = (
            f"Firewall {action}: {protocol} {src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port} (IN={in_iface} OUT={out_iface})"
        )

        metadata: dict[str, object] = {
            "action": action,
            "protocol": protocol,
            "source_port": src_port,
            "dest_port": dst_port,
            "in_interface": in_iface,
            "out_interface": out_iface,
            "ttl": ttl,
            "length": length,
            "prefix": prefix,
            "all_kv": kv,
        }
        if mac:
            metadata["mac"] = mac

        return ParsedEvent(
            timestamp=timestamp,
            source="iptables",
            source_ip=src_ip,
            dest_ip=dst_ip,
            hostname=hostname,
            service="kernel",
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Windows Firewall parser
    # ------------------------------------------------------------------

    def _parse_windows_firewall(self, raw: str) -> ParsedEvent | None:
        """Parse a Windows Firewall log line."""
        match = _WINFIREWALL_RE.match(raw)
        if not match:
            return None

        date_str = match.group("date")
        time_str = match.group("time")
        action = match.group("action")
        protocol = match.group("protocol")
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")
        src_port = match.group("src_port")
        dst_port = match.group("dst_port")
        rest = match.group("rest") or ""

        # Timestamp
        timestamp_str = f"{date_str} {time_str}"
        timestamp = self.extract_timestamp(timestamp_str)

        # Clean port fields
        src_port = src_port if src_port != "-" else ""
        dst_port = dst_port if dst_port != "-" else ""

        # Parse remaining fields (size, tcpflags, tcpsyn, tcpack, tcpwin, icmptype, icmpcode, info, path)
        rest_parts = rest.split()
        extra: dict[str, str] = {}
        field_names = ["size", "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path"]
        for i, name in enumerate(field_names):
            if i < len(rest_parts) and rest_parts[i] != "-":
                extra[name] = rest_parts[i]

        # Severity
        severity = self._compute_severity(action, dst_port, protocol)

        # Event type
        event_type = self._compute_event_type(action, protocol)

        # Message
        message = (
            f"Windows Firewall {action}: {protocol} {src_ip}:{src_port} -> "
            f"{dst_ip}:{dst_port}"
        )

        metadata: dict[str, object] = {
            "action": action,
            "protocol": protocol,
            "source_port": src_port,
            "dest_port": dst_port,
            **extra,
        }

        return ParsedEvent(
            timestamp=timestamp,
            source="windows_firewall",
            source_ip=src_ip,
            dest_ip=dst_ip,
            hostname="",
            service="windows_firewall",
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_severity(action: str, dst_port: str, protocol: str) -> str:
        """Determine severity from firewall action and destination port."""
        port_num: int | None = None
        try:
            port_num = int(dst_port) if dst_port else None
        except ValueError:
            pass

        # Dropped traffic to high-risk ports
        if action in ("DROP", "REJECT"):
            if port_num and port_num in _HIGH_RISK_PORTS:
                return "high"
            return "medium"

        # Allowed traffic to suspicious ports
        if action in ("ACCEPT", "ALLOW"):
            if port_num and port_num in _HIGH_RISK_PORTS:
                return "low"
            return "info"

        return "info"

    @staticmethod
    def _compute_event_type(action: str, protocol: str) -> str:
        """Determine the event type string."""
        action_lower = action.lower()
        proto_lower = protocol.lower() if protocol else "unknown"

        if action_lower in ("drop", "reject", "block"):
            return f"firewall_block_{proto_lower}"
        elif action_lower in ("accept", "allow", "open"):
            return f"firewall_allow_{proto_lower}"
        elif action_lower == "close":
            return f"firewall_close_{proto_lower}"
        return f"firewall_{action_lower}_{proto_lower}"
