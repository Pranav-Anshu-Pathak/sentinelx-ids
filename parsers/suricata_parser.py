"""SentinelX IDS - Suricata Log Parser.

Parses Suricata IDS output in two formats:

1. **EVE JSON** — structured JSON records (one per line) from ``eve.json``::

       {"timestamp":"2024-01-01T12:00:00.000000+0000","event_type":"alert",
        "src_ip":"1.2.3.4","src_port":54321,"dest_ip":"5.6.7.8","dest_port":80,
        "proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001,
        "rev":1,"signature":"ET MALWARE ...","category":"...","severity":1}}

2. **fast.log** — single-line plain-text alerts::

       01/01/2024-12:00:00.123456  [**] [1:2001:1] ET MALWARE ... [**]
       [Classification: ...] [Priority: 1] {TCP} 1.2.3.4:54321 -> 5.6.7.8:80
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from parsers.base_parser import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Pre-compiled patterns for fast.log
# ---------------------------------------------------------------------------

_FAST_LOG_RE: re.Pattern[str] = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.+?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s+)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)

# Alternative fast.log without ports (ICMP, etc.)
_FAST_LOG_NO_PORT_RE: re.Pattern[str] = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<message>.+?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s+)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+)"
)

# Suricata priority → SentinelX severity mapping
_PRIORITY_MAP: dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# Suricata severity (EVE JSON, 1=highest) → SentinelX severity
_SURICATA_SEVERITY_MAP: dict[int, str] = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


class SuricataParser(BaseParser):
    """Parser for Suricata EVE JSON and fast.log alert formats.

    Auto-detects the format by attempting JSON parse first, then falling
    back to fast.log regex parsing.
    """

    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a single Suricata log line.

        Args:
            raw_line: Raw line from ``eve.json`` or ``fast.log``.

        Returns:
            ``ParsedEvent`` on success, ``None`` if the line is not recognised.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Try EVE JSON first
        if raw_line.startswith("{"):
            event = self._parse_eve_json(raw_line)
            if event is not None:
                return event

        # Fall back to fast.log
        return self._parse_fast_log(raw_line)

    # ------------------------------------------------------------------
    # EVE JSON parser
    # ------------------------------------------------------------------

    def _parse_eve_json(self, raw: str) -> ParsedEvent | None:
        """Parse a Suricata EVE JSON line."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None

        # Only process alert events (skip flow, dns, http, etc.)
        eve_event_type = data.get("event_type", "")

        # Timestamp
        timestamp_str = data.get("timestamp", "")
        timestamp = self.extract_timestamp(timestamp_str) if timestamp_str else datetime.utcnow()

        # Network fields
        src_ip = data.get("src_ip", "")
        dst_ip = data.get("dest_ip", "")
        src_port = data.get("src_port", 0)
        dst_port = data.get("dest_port", 0)
        protocol = data.get("proto", "")

        # Flow info
        flow = data.get("flow", {})
        in_iface = data.get("in_iface", "")

        if eve_event_type == "alert":
            alert_data = data.get("alert", {})
            gid = alert_data.get("gid", 0)
            sid = alert_data.get("signature_id", 0)
            rev = alert_data.get("rev", 0)
            signature = alert_data.get("signature", "")
            category = alert_data.get("category", "")
            suricata_severity = alert_data.get("severity", 4)
            action = alert_data.get("action", "")

            severity = _SURICATA_SEVERITY_MAP.get(suricata_severity, "low")

            message = f"[{gid}:{sid}:{rev}] {signature}"
            if category:
                message += f" [Classification: {category}]"

            event_type = "suricata_alert"

            metadata: dict[str, object] = {
                "gid": gid,
                "sid": sid,
                "rev": rev,
                "signature": signature,
                "category": category,
                "suricata_severity": suricata_severity,
                "action": action,
                "protocol": protocol,
                "source_port": src_port,
                "dest_port": dst_port,
                "in_iface": in_iface,
                "flow": flow,
                "eve_event_type": eve_event_type,
            }
        else:
            # Non-alert EVE events (flow, dns, http, tls, etc.)
            severity = "info"
            event_type = f"suricata_{eve_event_type}"
            message = f"Suricata {eve_event_type}: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            metadata = {
                "protocol": protocol,
                "source_port": src_port,
                "dest_port": dst_port,
                "in_iface": in_iface,
                "eve_event_type": eve_event_type,
                "eve_data": data,
            }

            # Enrich HTTP events
            if eve_event_type == "http":
                http_data = data.get("http", {})
                metadata["http_method"] = http_data.get("http_method", "")
                metadata["http_url"] = http_data.get("url", "")
                metadata["http_status"] = http_data.get("status", 0)
                metadata["http_user_agent"] = http_data.get("http_user_agent", "")
                metadata["http_hostname"] = http_data.get("hostname", "")

            # Enrich DNS events
            elif eve_event_type == "dns":
                dns_data = data.get("dns", {})
                metadata["dns_type"] = dns_data.get("type", "")
                metadata["dns_rrname"] = dns_data.get("rrname", "")
                metadata["dns_rcode"] = dns_data.get("rcode", "")

        hostname = data.get("host", "") or data.get("hostname", "")

        return ParsedEvent(
            timestamp=timestamp,
            source="suricata",
            source_ip=src_ip,
            dest_ip=dst_ip,
            hostname=hostname,
            service="suricata",
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # fast.log parser
    # ------------------------------------------------------------------

    def _parse_fast_log(self, raw: str) -> ParsedEvent | None:
        """Parse a Suricata fast.log alert line."""
        match = _FAST_LOG_RE.match(raw)
        has_ports = True

        if not match:
            match = _FAST_LOG_NO_PORT_RE.match(raw)
            has_ports = False

        if not match:
            return None

        timestamp_str = match.group("timestamp")
        gid = int(match.group("gid"))
        sid = int(match.group("sid"))
        rev = int(match.group("rev"))
        alert_message = match.group("message").strip()
        classification = (match.group("classification") or "").strip()
        priority = int(match.group("priority"))
        protocol = match.group("protocol")
        src_ip = match.group("src_ip")
        dst_ip = match.group("dst_ip")

        src_port = int(match.group("src_port")) if has_ports else 0
        dst_port = int(match.group("dst_port")) if has_ports else 0

        # Timestamp
        timestamp = self.extract_timestamp(timestamp_str)

        # Severity from priority
        severity = _PRIORITY_MAP.get(priority, "low")

        # Message
        message = f"[{gid}:{sid}:{rev}] {alert_message}"
        if classification:
            message += f" [Classification: {classification}]"

        metadata: dict[str, object] = {
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "signature": alert_message,
            "category": classification,
            "priority": priority,
            "protocol": protocol,
            "source_port": src_port,
            "dest_port": dst_port,
        }

        return ParsedEvent(
            timestamp=timestamp,
            source="suricata",
            source_ip=src_ip,
            dest_ip=dst_ip,
            hostname="",
            service="suricata",
            message=message,
            severity=severity,
            event_type="suricata_alert",
            raw=raw,
            metadata=metadata,
        )
