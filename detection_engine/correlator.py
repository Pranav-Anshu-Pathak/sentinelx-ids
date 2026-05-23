"""SentinelX IDS - Event Correlator.

Provides advanced multi-event correlation across sliding time windows to
detect attack patterns that span multiple individual events:

- **Brute Force**: >10 failed logins from same IP in 60s followed by success.
- **Credential Stuffing**: Same password pattern against >5 usernames from same IP.
- **Lateral Movement**: Same source IP targets >3 hosts within 5 minutes.
- **Port Scan**: Same source IP connects to >20 ports on a single target in 60s.

Uses ``collections.deque`` with ``maxlen`` for bounded memory and
``asyncio.Lock`` for thread safety in async contexts.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("sentinelx.correlator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BRUTE_FORCE_THRESHOLD: int = 10
_BRUTE_FORCE_WINDOW: float = 60.0

_CRED_STUFFING_USERNAME_THRESHOLD: int = 5

_LATERAL_MOVEMENT_HOST_THRESHOLD: int = 3
_LATERAL_MOVEMENT_WINDOW: float = 300.0  # 5 minutes

_PORT_SCAN_PORT_THRESHOLD: int = 20
_PORT_SCAN_WINDOW: float = 60.0

_MAX_EVENTS_PER_KEY: int = 500  # maxlen for deques


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class CorrelationAlert:
    """Alert produced by the event correlator.

    Attributes:
        alert_type: Type of correlated attack (e.g. ``brute_force``).
        source_ip: The source IP involved.
        severity: Alert severity (``high`` or ``critical``).
        description: Human-readable description of the correlation finding.
        evidence_count: Number of contributing events.
        time_window: Time span (seconds) over which events were observed.
        first_seen: Epoch timestamp of the earliest contributing event.
        last_seen: Epoch timestamp of the most recent contributing event.
        metadata: Extra contextual information.
    """

    alert_type: str
    source_ip: str
    severity: str
    description: str
    evidence_count: int
    time_window: float
    first_seen: float
    last_seen: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _TimestampedEvent:
    """Minimal event record stored in sliding-window deques."""

    timestamp: float
    event_type: str
    source_ip: str
    dest_ip: str
    hostname: str
    dest_port: int
    username: str
    password_hash: str
    raw_message: str


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class EventCorrelator:
    """Stateful event correlator using sliding time windows.

    Thread-safe for use within ``asyncio`` — all mutations are guarded by
    an ``asyncio.Lock``.

    Usage::

        correlator = EventCorrelator()
        alerts = await correlator.correlate(event_dict)
        await correlator.clear_expired()
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

        # Keyed by source_ip → deque of _TimestampedEvent
        self._failed_logins: dict[str, deque[_TimestampedEvent]] = {}
        self._successful_logins: dict[str, deque[_TimestampedEvent]] = {}

        # Credential stuffing: source_ip → deque of (timestamp, username, password_hash)
        self._cred_attempts: dict[str, deque[_TimestampedEvent]] = {}

        # Lateral movement: source_ip → deque of (timestamp, target_host)
        self._lateral_events: dict[str, deque[_TimestampedEvent]] = {}

        # Port scan: (source_ip, dest_ip) → deque of (timestamp, dest_port)
        self._port_events: dict[tuple[str, str], deque[_TimestampedEvent]] = {}

        # Track already-fired alerts to avoid duplicates within a window
        self._fired_alerts: dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def correlate(self, event: dict[str, Any]) -> list[CorrelationAlert]:
        """Ingest an event and return any correlation alerts it triggers.

        The *event* dict is expected to have at least::

            {
                "source_ip": "...",
                "event_type": "...",    # e.g. auth_failure, auth_success
                "message": "...",
                "hostname": "...",       # optional
                "dest_ip": "...",        # optional
                "dest_port": 0,          # optional, int
                "metadata": {            # optional
                    "username": "...",
                    "password_hash": "..."
                }
            }

        Args:
            event: Structured event dictionary.

        Returns:
            List of ``CorrelationAlert`` objects (may be empty).
        """
        alerts: list[CorrelationAlert] = []
        now = time.time()

        source_ip = str(event.get("source_ip", ""))
        if not source_ip:
            return alerts

        event_type = str(event.get("event_type", ""))
        dest_ip = str(event.get("dest_ip", ""))
        hostname = str(event.get("hostname", ""))
        message = str(event.get("message", ""))
        metadata = event.get("metadata", {}) or {}

        dest_port: int = 0
        raw_port = event.get("dest_port") or metadata.get("dest_port", 0)
        try:
            dest_port = int(raw_port)
        except (ValueError, TypeError):
            pass

        username = str(metadata.get("username", ""))
        password_hash = str(metadata.get("password_hash", ""))

        te = _TimestampedEvent(
            timestamp=now,
            event_type=event_type,
            source_ip=source_ip,
            dest_ip=dest_ip,
            hostname=hostname,
            dest_port=dest_port,
            username=username,
            password_hash=password_hash,
            raw_message=message,
        )

        async with self._lock:
            # ---- Track events ----
            is_auth_failure = event_type in (
                "auth_failure", "auth_failure_invalid_user",
                "pam_auth_failure", "logon_failure",
                "max_auth_exceeded",
            )
            is_auth_success = event_type in ("auth_success", "logon_success")

            if is_auth_failure:
                self._append_event(self._failed_logins, source_ip, te)
                if username:
                    self._append_event(self._cred_attempts, source_ip, te)

            if is_auth_success:
                self._append_event(self._successful_logins, source_ip, te)

            # Lateral movement tracking — any connection/auth to a different host
            target = hostname or dest_ip
            if target:
                self._append_event(self._lateral_events, source_ip, te)

            # Port scan tracking
            if dest_port and dest_ip:
                key = (source_ip, dest_ip)
                if key not in self._port_events:
                    self._port_events[key] = deque(maxlen=_MAX_EVENTS_PER_KEY)
                self._port_events[key].append(te)

            # ---- Run detections ----
            bf_alert = self._detect_brute_force(source_ip, now)
            if bf_alert:
                alerts.append(bf_alert)

            cs_alert = self._detect_credential_stuffing(source_ip, now)
            if cs_alert:
                alerts.append(cs_alert)

            lm_alert = self._detect_lateral_movement(source_ip, now)
            if lm_alert:
                alerts.append(lm_alert)

            if dest_ip:
                ps_alert = self._detect_port_scan(source_ip, dest_ip, now)
                if ps_alert:
                    alerts.append(ps_alert)

        return alerts

    async def clear_expired(self, max_age: float = 600.0) -> int:
        """Remove events older than *max_age* seconds from all tracking stores.

        Args:
            max_age: Maximum event age in seconds (default 10 minutes).

        Returns:
            Total number of events purged.
        """
        cutoff = time.time() - max_age
        purged = 0

        async with self._lock:
            purged += self._purge_store(self._failed_logins, cutoff)
            purged += self._purge_store(self._successful_logins, cutoff)
            purged += self._purge_store(self._cred_attempts, cutoff)
            purged += self._purge_store(self._lateral_events, cutoff)

            # Port events use tuple keys
            empty_keys: list[tuple[str, str]] = []
            for key, dq in self._port_events.items():
                before = len(dq)
                while dq and dq[0].timestamp < cutoff:
                    dq.popleft()
                purged += before - len(dq)
                if not dq:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._port_events[key]

            # Purge stale fired-alert records
            stale_keys = [k for k, t in self._fired_alerts.items() if t < cutoff]
            for k in stale_keys:
                del self._fired_alerts[k]

        logger.debug("Purged %d expired events", purged)
        return purged

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _detect_brute_force(self, source_ip: str, now: float) -> CorrelationAlert | None:
        """Detect brute-force: >10 failures in 60s AND a subsequent success."""
        alert_key = f"brute_force:{source_ip}"
        if self._recently_fired(alert_key, now):
            return None

        failures = self._failed_logins.get(source_ip)
        if not failures:
            return None

        # Count failures within window
        window_start = now - _BRUTE_FORCE_WINDOW
        recent_failures = [e for e in failures if e.timestamp >= window_start]

        if len(recent_failures) < _BRUTE_FORCE_THRESHOLD:
            return None

        # Check for a subsequent successful login
        successes = self._successful_logins.get(source_ip)
        if not successes:
            return None

        last_failure_time = recent_failures[-1].timestamp
        success_after_failures = any(
            s.timestamp >= last_failure_time for s in successes
        )

        if not success_after_failures:
            return None

        self._fired_alerts[alert_key] = now

        usernames = list({e.username for e in recent_failures if e.username})

        return CorrelationAlert(
            alert_type="brute_force",
            source_ip=source_ip,
            severity="critical",
            description=(
                f"Brute force detected: {len(recent_failures)} failed logins from "
                f"{source_ip} in {_BRUTE_FORCE_WINDOW}s followed by successful login"
            ),
            evidence_count=len(recent_failures) + 1,
            time_window=_BRUTE_FORCE_WINDOW,
            first_seen=recent_failures[0].timestamp,
            last_seen=now,
            metadata={
                "targeted_usernames": usernames,
                "failure_count": len(recent_failures),
            },
        )

    def _detect_credential_stuffing(self, source_ip: str, now: float) -> CorrelationAlert | None:
        """Detect credential stuffing: same password hash against >5 different usernames."""
        alert_key = f"cred_stuffing:{source_ip}"
        if self._recently_fired(alert_key, now):
            return None

        attempts = self._cred_attempts.get(source_ip)
        if not attempts:
            return None

        # Group by password_hash, count distinct usernames
        window_start = now - _BRUTE_FORCE_WINDOW
        recent = [e for e in attempts if e.timestamp >= window_start]

        password_to_users: dict[str, set[str]] = {}
        for e in recent:
            if e.password_hash and e.username:
                password_to_users.setdefault(e.password_hash, set()).add(e.username)

        for pwd_hash, users in password_to_users.items():
            if len(users) >= _CRED_STUFFING_USERNAME_THRESHOLD:
                self._fired_alerts[alert_key] = now
                return CorrelationAlert(
                    alert_type="credential_stuffing",
                    source_ip=source_ip,
                    severity="critical",
                    description=(
                        f"Credential stuffing detected: same password pattern tried "
                        f"against {len(users)} different usernames from {source_ip}"
                    ),
                    evidence_count=len(recent),
                    time_window=_BRUTE_FORCE_WINDOW,
                    first_seen=recent[0].timestamp,
                    last_seen=now,
                    metadata={
                        "targeted_usernames": sorted(users),
                        "distinct_username_count": len(users),
                    },
                )

        return None

    def _detect_lateral_movement(self, source_ip: str, now: float) -> CorrelationAlert | None:
        """Detect lateral movement: same IP targets >3 different hosts in 5 minutes."""
        alert_key = f"lateral_movement:{source_ip}"
        if self._recently_fired(alert_key, now):
            return None

        events = self._lateral_events.get(source_ip)
        if not events:
            return None

        window_start = now - _LATERAL_MOVEMENT_WINDOW
        recent = [e for e in events if e.timestamp >= window_start]

        target_hosts: set[str] = set()
        for e in recent:
            target = e.hostname or e.dest_ip
            if target:
                target_hosts.add(target)

        if len(target_hosts) <= _LATERAL_MOVEMENT_HOST_THRESHOLD:
            return None

        self._fired_alerts[alert_key] = now

        return CorrelationAlert(
            alert_type="lateral_movement",
            source_ip=source_ip,
            severity="high",
            description=(
                f"Lateral movement detected: {source_ip} targeted "
                f"{len(target_hosts)} different hosts in {_LATERAL_MOVEMENT_WINDOW}s"
            ),
            evidence_count=len(recent),
            time_window=_LATERAL_MOVEMENT_WINDOW,
            first_seen=recent[0].timestamp,
            last_seen=now,
            metadata={
                "target_hosts": sorted(target_hosts),
                "distinct_host_count": len(target_hosts),
            },
        )

    def _detect_port_scan(
        self,
        source_ip: str,
        dest_ip: str,
        now: float,
    ) -> CorrelationAlert | None:
        """Detect port scan: same IP → >20 ports on same target in 60s."""
        key = (source_ip, dest_ip)
        alert_key = f"port_scan:{source_ip}:{dest_ip}"
        if self._recently_fired(alert_key, now):
            return None

        events = self._port_events.get(key)
        if not events:
            return None

        window_start = now - _PORT_SCAN_WINDOW
        recent = [e for e in events if e.timestamp >= window_start]

        ports: set[int] = {e.dest_port for e in recent if e.dest_port}

        if len(ports) <= _PORT_SCAN_PORT_THRESHOLD:
            return None

        self._fired_alerts[alert_key] = now

        return CorrelationAlert(
            alert_type="port_scan",
            source_ip=source_ip,
            severity="high",
            description=(
                f"Port scan detected: {source_ip} connected to "
                f"{len(ports)} different ports on {dest_ip} in {_PORT_SCAN_WINDOW}s"
            ),
            evidence_count=len(recent),
            time_window=_PORT_SCAN_WINDOW,
            first_seen=recent[0].timestamp,
            last_seen=now,
            metadata={
                "target_ip": dest_ip,
                "scanned_ports": sorted(ports),
                "distinct_port_count": len(ports),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append_event(
        store: dict[str, deque[_TimestampedEvent]],
        key: str,
        event: _TimestampedEvent,
    ) -> None:
        """Append an event to a keyed deque store, creating the deque if needed."""
        if key not in store:
            store[key] = deque(maxlen=_MAX_EVENTS_PER_KEY)
        store[key].append(event)

    def _recently_fired(self, alert_key: str, now: float, cooldown: float = 60.0) -> bool:
        """Check if an alert was fired recently (within *cooldown* seconds)."""
        last_fired = self._fired_alerts.get(alert_key)
        if last_fired is not None and (now - last_fired) < cooldown:
            return True
        return False

    @staticmethod
    def _purge_store(
        store: dict[str, deque[_TimestampedEvent]],
        cutoff: float,
    ) -> int:
        """Remove events older than *cutoff* from a keyed deque store."""
        purged = 0
        empty_keys: list[str] = []
        for key, dq in store.items():
            before = len(dq)
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            purged += before - len(dq)
            if not dq:
                empty_keys.append(key)
        for key in empty_keys:
            del store[key]
        return purged
