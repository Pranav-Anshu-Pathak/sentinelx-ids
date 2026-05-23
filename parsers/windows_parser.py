"""SentinelX IDS - Windows Event Log Parser.

Parses Windows Event Log entries in XML format as exported by ``wevtutil``
or forwarded via Windows Event Forwarding (WEF).  Maps well-known Event IDs
to meaningful security categories and severity levels.

Supported Event IDs:
    4624 – Successful logon
    4625 – Failed logon
    4672 – Special privileges assigned to new logon
    4688 – A new process has been created
    4720 – A user account was created
    4732 – A member was added to a security-enabled local group
    1102 – The audit log was cleared
    7045 – A service was installed in the system
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime

from parsers.base_parser import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Event ID → metadata mapping
# ---------------------------------------------------------------------------

_EVENT_ID_MAP: dict[int, dict[str, str]] = {
    4624: {
        "event_type": "logon_success",
        "severity": "info",
        "description": "Successful logon",
    },
    4625: {
        "event_type": "logon_failure",
        "severity": "medium",
        "description": "Failed logon attempt",
    },
    4672: {
        "event_type": "special_privileges",
        "severity": "high",
        "description": "Special privileges assigned to new logon",
    },
    4688: {
        "event_type": "process_creation",
        "severity": "info",
        "description": "A new process has been created",
    },
    4720: {
        "event_type": "user_created",
        "severity": "medium",
        "description": "A user account was created",
    },
    4732: {
        "event_type": "group_member_added",
        "severity": "high",
        "description": "A member was added to a security-enabled local group",
    },
    1102: {
        "event_type": "audit_log_cleared",
        "severity": "critical",
        "description": "The audit log was cleared",
    },
    7045: {
        "event_type": "service_installed",
        "severity": "high",
        "description": "A service was installed in the system",
    },
}

# Well-known Logon Type descriptions
_LOGON_TYPES: dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# Suspicious processes that should elevate severity for Event 4688
_SUSPICIOUS_PROCESSES: re.Pattern[str] = re.compile(
    r"(?i)(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|"
    r"certutil|bitsadmin|msiexec|wmic|net\.exe|net1\.exe|psexec|"
    r"mimikatz|procdump|lazagne|rubeus|sharphound)",
)

# XML namespace commonly used in Windows Event Log XML
_WINLOG_NS: dict[str, str] = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}

# Regex for extracting simple XML-like event log entries (non-namespace)
_SIMPLE_XML_EVENT_ID_RE = re.compile(r"<EventID[^>]*>(\d+)</EventID>", re.IGNORECASE)
_SIMPLE_XML_TIMESTAMP_RE = re.compile(
    r'SystemTime=["\']([^"\']+)["\']', re.IGNORECASE
)
_SIMPLE_XML_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>", re.IGNORECASE)
_SIMPLE_XML_DATA_RE = re.compile(
    r'<Data\s+Name=["\'](\w+)["\']>([^<]*)</Data>', re.IGNORECASE
)
_SIMPLE_XML_PROVIDER_RE = re.compile(
    r'<Provider\s+Name=["\']([^"\']+)["\']', re.IGNORECASE
)


class WindowsEventParser(BaseParser):
    """Parser for Windows Event Log XML entries.

    Handles both namespace-qualified and plain XML event records.
    Provides deep extraction of security-relevant data fields and maps
    well-known Event IDs to severity levels and event types.
    """

    def parse(self, raw_line: str) -> ParsedEvent | None:
        """Parse a Windows Event Log XML record.

        Args:
            raw_line: A complete XML ``<Event>`` element as a string.

        Returns:
            ``ParsedEvent`` on success, ``None`` if parsing fails.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        # Attempt full XML parse first, fall back to regex extraction
        try:
            return self._parse_xml(raw_line)
        except ET.ParseError:
            return self._parse_regex(raw_line)

    # ------------------------------------------------------------------
    # Full XML parse path
    # ------------------------------------------------------------------

    def _parse_xml(self, raw: str) -> ParsedEvent | None:
        """Parse using the ElementTree XML parser."""
        root = ET.fromstring(raw)

        # Detect namespace
        ns = ""
        tag = root.tag
        if "}" in tag:
            ns = tag.split("}")[0] + "}"

        # Extract System fields
        event_id_elem = root.find(f".//{ns}EventID")
        event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

        time_elem = root.find(f".//{ns}TimeCreated")
        timestamp_str = ""
        if time_elem is not None:
            timestamp_str = time_elem.get("SystemTime", "")

        computer_elem = root.find(f".//{ns}Computer")
        hostname = computer_elem.text if computer_elem is not None and computer_elem.text else ""

        provider_elem = root.find(f".//{ns}Provider")
        service = provider_elem.get("Name", "") if provider_elem is not None else ""

        # Extract EventData fields
        data_fields: dict[str, str] = {}
        for data_elem in root.findall(f".//{ns}Data"):
            name = data_elem.get("Name", "")
            value = data_elem.text or ""
            if name:
                data_fields[name] = value

        return self._build_event(event_id, timestamp_str, hostname, service, data_fields, raw)

    # ------------------------------------------------------------------
    # Regex-based fallback parse path
    # ------------------------------------------------------------------

    def _parse_regex(self, raw: str) -> ParsedEvent | None:
        """Parse using regex patterns when XML parsing fails."""
        event_id_match = _SIMPLE_XML_EVENT_ID_RE.search(raw)
        if not event_id_match:
            return None
        event_id = int(event_id_match.group(1))

        timestamp_match = _SIMPLE_XML_TIMESTAMP_RE.search(raw)
        timestamp_str = timestamp_match.group(1) if timestamp_match else ""

        computer_match = _SIMPLE_XML_COMPUTER_RE.search(raw)
        hostname = computer_match.group(1) if computer_match else ""

        provider_match = _SIMPLE_XML_PROVIDER_RE.search(raw)
        service = provider_match.group(1) if provider_match else ""

        data_fields: dict[str, str] = {}
        for match in _SIMPLE_XML_DATA_RE.finditer(raw):
            data_fields[match.group(1)] = match.group(2)

        return self._build_event(event_id, timestamp_str, hostname, service, data_fields, raw)

    # ------------------------------------------------------------------
    # Shared builder
    # ------------------------------------------------------------------

    def _build_event(
        self,
        event_id: int,
        timestamp_str: str,
        hostname: str,
        service: str,
        data_fields: dict[str, str],
        raw: str,
    ) -> ParsedEvent:
        """Build a ``ParsedEvent`` from extracted components."""
        # Timestamp
        timestamp = self.extract_timestamp(timestamp_str) if timestamp_str else datetime.utcnow()

        # Map Event ID
        eid_info = _EVENT_ID_MAP.get(event_id, {
            "event_type": f"windows_event_{event_id}",
            "severity": "info",
            "description": f"Windows Event ID {event_id}",
        })

        event_type: str = eid_info["event_type"]
        severity: str = eid_info["severity"]
        description: str = eid_info["description"]

        # Extract well-known data fields
        target_user = data_fields.get("TargetUserName", "")
        ip_address = data_fields.get("IpAddress", "")
        logon_type = data_fields.get("LogonType", "")
        process_name = data_fields.get("NewProcessName", "") or data_fields.get("ProcessName", "")
        subject_user = data_fields.get("SubjectUserName", "")
        target_domain = data_fields.get("TargetDomainName", "")
        workstation = data_fields.get("WorkstationName", "")
        status = data_fields.get("Status", "")
        sub_status = data_fields.get("SubStatus", "")
        member_name = data_fields.get("MemberName", "")
        member_sid = data_fields.get("MemberSid", "")
        group_name = data_fields.get("TargetUserName", "")
        service_name = data_fields.get("ServiceName", "")
        service_file = data_fields.get("ImagePath", "") or data_fields.get("ServiceFileName", "")

        # Clean up IP (Windows sometimes uses '-' for empty)
        if ip_address in ("-", "::1", "127.0.0.1"):
            source_ip = ip_address
        else:
            source_ip = ip_address if ip_address else self.extract_ip(raw)

        # Build descriptive message
        message = description
        if target_user:
            message += f" | User: {target_user}"
        if ip_address:
            message += f" | IP: {ip_address}"
        if logon_type:
            logon_desc = _LOGON_TYPES.get(logon_type, logon_type)
            message += f" | LogonType: {logon_desc}"
        if process_name:
            message += f" | Process: {process_name}"

        # Adjust severity for specific conditions
        severity = self._adjust_severity(event_id, severity, logon_type, process_name, data_fields)

        # Metadata
        metadata: dict[str, object] = {
            "event_id": event_id,
            "target_user": target_user,
            "subject_user": subject_user,
            "target_domain": target_domain,
            "logon_type": logon_type,
            "logon_type_desc": _LOGON_TYPES.get(logon_type, ""),
            "process_name": process_name,
            "workstation": workstation,
            "status": status,
            "sub_status": sub_status,
            "data_fields": data_fields,
        }

        if member_name:
            metadata["member_name"] = member_name
            metadata["member_sid"] = member_sid
        if group_name and event_id == 4732:
            metadata["group_name"] = group_name
        if service_name:
            metadata["service_name"] = service_name
            metadata["service_file"] = service_file

        return ParsedEvent(
            timestamp=timestamp,
            source="windows_event",
            source_ip=source_ip,
            dest_ip="",
            hostname=hostname,
            service=service,
            message=message,
            severity=severity,
            event_type=event_type,
            raw=raw,
            metadata=metadata,
        )

    @staticmethod
    def _adjust_severity(
        event_id: int,
        current: str,
        logon_type: str,
        process_name: str,
        data_fields: dict[str, str],
    ) -> str:
        """Conditionally elevate severity based on contextual signals."""
        # 4688 with a suspicious process name → high
        if event_id == 4688 and _SUSPICIOUS_PROCESSES.search(process_name):
            return "high"

        # 4625 with logon type 10 (RDP) → high
        if event_id == 4625 and logon_type == "10":
            return "high"

        # 4624 with logon type 10 from external IP → medium
        if event_id == 4624 and logon_type == "10":
            ip = data_fields.get("IpAddress", "")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                return "medium"

        return current
