"""SentinelX IDS - Log Parsers Package.

Provides parsers for various log formats including syslog, Windows Event Log,
firewall logs, web server logs, and Suricata IDS output.
"""

from parsers.base_parser import BaseParser, ParsedEvent
from parsers.syslog_parser import SyslogParser
from parsers.windows_parser import WindowsEventParser
from parsers.firewall_parser import FirewallParser
from parsers.web_parser import WebServerParser
from parsers.suricata_parser import SuricataParser

__all__ = [
    "BaseParser",
    "ParsedEvent",
    "SyslogParser",
    "WindowsEventParser",
    "FirewallParser",
    "WebServerParser",
    "SuricataParser",
]
