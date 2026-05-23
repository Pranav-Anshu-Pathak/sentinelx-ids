"""Demo log generator for development and demonstration."""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from backend.config import settings

logger = logging.getLogger("sentinelx.collector")

# Sample messages aligned with bundled detection rules
DEMO_EVENTS: list[dict[str, Any]] = [
    {
        "raw_message": "Failed password for invalid user admin from 203.0.113.42 port 22 ssh2",
        "source": "syslog",
        "source_ip": "203.0.113.42",
        "hostname": "auth-gateway",
        "severity": "high",
        "service": "sshd",
        "event_type": "auth_failure",
    },
    {
        "raw_message": "Failed password for root from 192.168.1.105 port 49152 ssh2",
        "source": "syslog",
        "source_ip": "192.168.1.105",
        "hostname": "web-prod-01",
        "severity": "high",
        "service": "sshd",
        "event_type": "auth_failure",
    },
    {
        "raw_message": "SCAN nmap -sS detected from 172.16.0.33 targeting ports 1-1024",
        "source": "firewall",
        "source_ip": "172.16.0.33",
        "dest_ip": "10.0.0.5",
        "hostname": "firewall-01",
        "severity": "medium",
        "service": "iptables",
        "event_type": "port_scan",
    },
    {
        "raw_message": "BLOCKED outbound connection to 185.220.101.1:4444 reverse shell pattern",
        "source": "suricata",
        "source_ip": "10.0.0.44",
        "dest_ip": "185.220.101.1",
        "hostname": "endpoint-42",
        "severity": "critical",
        "service": "suricata",
        "event_type": "reverse_shell",
    },
    {
        "raw_message": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdA== executed by user CORP\\jsmith",
        "source": "windows",
        "source_ip": "10.0.1.88",
        "hostname": "workstation-07",
        "severity": "critical",
        "service": "powershell",
        "event_type": "encoded_command",
    },
    {
        "raw_message": "sudo: user www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "source": "syslog",
        "source_ip": "10.0.0.12",
        "hostname": "db-master",
        "severity": "high",
        "service": "sudo",
        "event_type": "privilege_escalation",
    },
    {
        "raw_message": "SMB lateral movement attempt from 10.0.0.44 to 10.0.0.5 admin$ share",
        "source": "windows",
        "source_ip": "10.0.0.44",
        "dest_ip": "10.0.0.5",
        "hostname": "file-server",
        "severity": "high",
        "service": "smb",
        "event_type": "lateral_movement",
    },
    {
        "raw_message": "HTTP POST 15MB to external host data-exfil.example.com from 192.168.2.201",
        "source": "web",
        "source_ip": "192.168.2.201",
        "dest_ip": "93.184.216.34",
        "hostname": "api-gateway",
        "severity": "high",
        "service": "nginx",
        "event_type": "data_exfiltration",
    },
    {
        "raw_message": "Accepted publickey for deploy from 10.0.1.5 port 22 ssh2",
        "source": "syslog",
        "source_ip": "10.0.1.5",
        "hostname": "ci-runner",
        "severity": "info",
        "service": "sshd",
        "event_type": "auth_success",
    },
    {
        "raw_message": "GET /api/health 200 12ms from 127.0.0.1",
        "source": "web",
        "source_ip": "127.0.0.1",
        "hostname": "api-gateway",
        "severity": "info",
        "service": "nginx",
        "event_type": "http_request",
    },
]


async def run_demo_collector(
    on_event: Callable[[dict[str, Any]], Awaitable[None]],
    stop_event: asyncio.Event,
) -> None:
    """Emit synthetic security events at random intervals."""
    if not settings.DEMO_MODE:
        return

    logger.info("Demo log collector started")
    while not stop_event.is_set():
        event = random.choice(DEMO_EVENTS).copy()
        event["timestamp"] = datetime.now(timezone.utc)
        try:
            await on_event(event)
        except Exception as exc:
            logger.error("Demo collector handler error: %s", exc)

        delay = random.uniform(settings.SIM_INTERVAL_MIN, settings.SIM_INTERVAL_MAX)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    logger.info("Demo log collector stopped")
