"""SentinelX IDS - Anomaly Scorer.

Scores events on a 0.0-1.0 scale using statistical methods (z-score, IQR)
and maintains rolling baselines per source_ip and event_type. Operates
entirely offline without external dependencies.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class BaselineStats:
    """Rolling statistics for a specific key (source_ip or event_type)."""

    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    values: deque[float] = field(default_factory=lambda: deque(maxlen=1000))
    count: int = 0
    last_seen: float = 0.0

    @property
    def mean(self) -> float:
        """Compute arithmetic mean of stored values."""
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def std_dev(self) -> float:
        """Compute standard deviation of stored values."""
        if len(self.values) < 2:
            return 0.0
        m = self.mean
        variance = sum((x - m) ** 2 for x in self.values) / len(self.values)
        return math.sqrt(variance)

    @property
    def q1(self) -> float:
        """Compute 25th percentile (Q1)."""
        return self._percentile(25)

    @property
    def q3(self) -> float:
        """Compute 75th percentile (Q3)."""
        return self._percentile(75)

    @property
    def iqr(self) -> float:
        """Compute interquartile range."""
        return self.q3 - self.q1

    def _percentile(self, p: int) -> float:
        """Compute the p-th percentile of stored values."""
        if not self.values:
            return 0.0
        sorted_vals = sorted(self.values)
        k = (len(sorted_vals) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_vals):
            return sorted_vals[f]
        d = k - f
        return sorted_vals[f] + d * (sorted_vals[c] - sorted_vals[f])

    def events_per_minute(self, window_seconds: int = 300) -> float:
        """Compute events per minute within a rolling window."""
        now = time.time()
        cutoff = now - window_seconds
        recent = sum(1 for ts in self.timestamps if ts > cutoff)
        minutes = window_seconds / 60.0
        return recent / minutes if minutes > 0 else 0.0


# ---------------------------------------------------------------------------
# Known suspicious geo locations (for offline scoring)
# ---------------------------------------------------------------------------

_SUSPICIOUS_COUNTRIES: set[str] = {
    "CN", "RU", "KP", "IR", "SY", "VN", "NG", "RO", "UA", "BR",
}

# ---------------------------------------------------------------------------
# Normal business hours (local server time)
# ---------------------------------------------------------------------------

_BUSINESS_HOURS_START = 7   # 07:00
_BUSINESS_HOURS_END = 19    # 19:00


class AnomalyScorer:
    """Scores events on a 0.0-1.0 anomaly scale using statistical baselines.

    Features scored:
        - time_of_day_score: Events outside business hours score higher
        - frequency_score: Unusual event frequency per source_ip
        - geo_anomaly_score: Events from suspicious geo locations
        - pattern_score: Events matching known attack patterns

    Maintains rolling baselines per source_ip and event_type for adaptive
    anomaly detection using z-score and IQR methods.
    """

    def __init__(
        self,
        baseline_window: int = 1000,
        business_hours: tuple[int, int] = (_BUSINESS_HOURS_START, _BUSINESS_HOURS_END),
    ) -> None:
        self._ip_baselines: dict[str, BaselineStats] = defaultdict(BaselineStats)
        self._type_baselines: dict[str, BaselineStats] = defaultdict(BaselineStats)
        self._global_baseline: BaselineStats = BaselineStats()
        self._baseline_window = baseline_window
        self._business_start, self._business_end = business_hours

    def score_event(self, event: dict[str, Any]) -> float:
        """Score an event for anomalousness on a 0.0-1.0 scale.

        Args:
            event: Dictionary containing event data with optional fields:
                - timestamp (ISO string or Unix epoch)
                - source_ip
                - event_type / category
                - country / geo_country
                - message / raw_log
                - severity
                - port / destination_port
                - bytes_transferred

        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (highly anomalous).
        """
        now = time.time()
        source_ip = event.get("source_ip", "unknown")
        event_type = event.get("event_type", event.get("category", "unknown"))
        ts = self._parse_timestamp(event.get("timestamp", now))

        # Update baselines
        self._update_baselines(source_ip, event_type, ts, event)

        # Compute individual scores
        tod_score = self._time_of_day_score(ts)
        freq_score = self._frequency_score(source_ip, event_type)
        geo_score = self._geo_anomaly_score(event)
        pattern_score = self._pattern_score(event)

        # Severity boost
        severity_boost = self._severity_boost(event.get("severity", ""))

        # Weighted aggregation
        raw_score = (
            tod_score * 0.15
            + freq_score * 0.30
            + geo_score * 0.20
            + pattern_score * 0.25
            + severity_boost * 0.10
        )

        return round(min(1.0, max(0.0, raw_score)), 4)

    # ------------------------------------------------------------------
    # Feature Scorers
    # ------------------------------------------------------------------

    def _time_of_day_score(self, timestamp: float) -> float:
        """Score based on time of day — off-hours activity is more suspicious.

        Returns 0.0 during business hours, up to 1.0 in early morning hours.
        """
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour

        if self._business_start <= hour < self._business_end:
            return 0.0
        # Midnight to 5 AM is most suspicious
        if 0 <= hour < 5:
            return 0.9
        # 5-7 AM and 7-10 PM are moderately suspicious
        if 5 <= hour < self._business_start:
            return 0.4
        if self._business_end <= hour < 22:
            return 0.3
        # 10 PM to midnight
        return 0.7

    def _frequency_score(self, source_ip: str, event_type: str) -> float:
        """Score based on event frequency relative to baseline.

        Uses z-score of the current event rate compared to the rolling
        baseline for this source_ip.
        """
        ip_stats = self._ip_baselines[source_ip]
        epm = ip_stats.events_per_minute(window_seconds=300)

        if ip_stats.count < 5:
            # Not enough data — use moderate score if activity is present
            return min(1.0, epm / 10.0)

        mean_rate = ip_stats.mean
        std = ip_stats.std_dev

        if std < 0.001:
            # Very consistent rate — any spike is anomalous
            return min(1.0, max(0.0, (epm - mean_rate) * 0.5))

        # Z-score method
        z = (epm - mean_rate) / std
        # Convert z-score to 0-1 scale (z=2 → ~0.7, z=3 → ~0.9)
        score = 1.0 / (1.0 + math.exp(-0.8 * (z - 1.5)))
        return min(1.0, max(0.0, score))

    @staticmethod
    def _geo_anomaly_score(event: dict[str, Any]) -> float:
        """Score based on geographic origin — suspicious countries score higher."""
        country = event.get("country", event.get("geo_country", "")).upper()
        if not country:
            return 0.3  # Unknown geo is mildly suspicious

        if country in _SUSPICIOUS_COUNTRIES:
            return 0.85

        # Common expected countries score low
        expected = {"US", "GB", "CA", "AU", "DE", "FR", "JP", "NL", "SE", "NO"}
        if country in expected:
            return 0.05

        return 0.3  # Neutral countries

    @staticmethod
    def _pattern_score(event: dict[str, Any]) -> float:
        """Score based on pattern matching against known attack signatures."""
        message = str(event.get("message", "") or event.get("raw_log", "")).lower()
        if not message:
            return 0.0

        # Pattern weights — higher weight = more suspicious
        patterns: list[tuple[str, float]] = [
            (r"failed password for", 0.4),
            (r"invalid user", 0.5),
            (r"reverse.?shell|/dev/tcp|bash\s+-i", 0.95),
            (r"encodedcommand|-enc\s", 0.85),
            (r"privilege.?escalat|sudo.*root", 0.75),
            (r"web.?shell|cmd=|exec=", 0.9),
            (r"port.?scan|nmap", 0.5),
            (r"exfiltrat|data.?transfer", 0.8),
            (r"crypto.?min|xmrig|stratum", 0.7),
            (r"union.*select|or\s+1\s*=\s*1|drop\s+table", 0.85),
            (r"dns.?tunnel|iodine|dnscat", 0.8),
            (r"mimikatz|hashdump|lsass", 0.95),
            (r"accepted password for", 0.1),
            (r"session opened", 0.05),
        ]

        max_score = 0.0
        for pattern, weight in patterns:
            if re.search(pattern, message):
                max_score = max(max_score, weight)

        return max_score

    @staticmethod
    def _severity_boost(severity: str) -> float:
        """Convert severity label to a boost value."""
        severity_map: dict[str, float] = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
            "informational": 0.05,
        }
        return severity_map.get(severity.lower(), 0.3)

    # ------------------------------------------------------------------
    # Baseline Management
    # ------------------------------------------------------------------

    def _update_baselines(
        self,
        source_ip: str,
        event_type: str,
        timestamp: float,
        event: dict[str, Any],
    ) -> None:
        """Update rolling baselines with new event data."""
        now = time.time()

        # Update IP baseline
        ip_stats = self._ip_baselines[source_ip]
        ip_stats.timestamps.append(timestamp)
        ip_stats.count += 1
        epm = ip_stats.events_per_minute()
        ip_stats.values.append(epm)
        ip_stats.last_seen = now

        # Update event type baseline
        type_stats = self._type_baselines[event_type]
        type_stats.timestamps.append(timestamp)
        type_stats.count += 1
        type_stats.values.append(type_stats.events_per_minute())
        type_stats.last_seen = now

        # Update global baseline
        self._global_baseline.timestamps.append(timestamp)
        self._global_baseline.count += 1
        self._global_baseline.values.append(self._global_baseline.events_per_minute())

    def get_baseline(self, source_ip: str) -> dict[str, Any]:
        """Return current baseline statistics for a source IP.

        Args:
            source_ip: The IP address to look up.

        Returns:
            Dictionary with baseline metrics.
        """
        stats = self._ip_baselines.get(source_ip)
        if not stats or stats.count == 0:
            return {
                "source_ip": source_ip,
                "total_events": 0,
                "events_per_minute": 0.0,
                "mean_rate": 0.0,
                "std_dev": 0.0,
                "iqr": 0.0,
            }
        return {
            "source_ip": source_ip,
            "total_events": stats.count,
            "events_per_minute": round(stats.events_per_minute(), 4),
            "mean_rate": round(stats.mean, 4),
            "std_dev": round(stats.std_dev, 4),
            "iqr": round(stats.iqr, 4),
            "q1": round(stats.q1, 4),
            "q3": round(stats.q3, 4),
        }

    def get_all_baselines(self) -> dict[str, dict[str, Any]]:
        """Return baselines for all tracked source IPs."""
        return {ip: self.get_baseline(ip) for ip in self._ip_baselines}

    def reset_baseline(self, source_ip: str) -> None:
        """Reset the baseline for a specific source IP."""
        if source_ip in self._ip_baselines:
            del self._ip_baselines[source_ip]

    def reset_all(self) -> None:
        """Reset all baselines."""
        self._ip_baselines.clear()
        self._type_baselines.clear()
        self._global_baseline = BaselineStats()

    # ------------------------------------------------------------------
    # IQR-based Outlier Detection
    # ------------------------------------------------------------------

    def is_outlier_iqr(self, source_ip: str, value: float) -> bool:
        """Determine if a value is an outlier using the IQR method.

        Args:
            source_ip: IP address for baseline lookup.
            value: The value to test.

        Returns:
            True if the value is outside 1.5×IQR from Q1/Q3.
        """
        stats = self._ip_baselines.get(source_ip)
        if not stats or stats.count < 10:
            return False

        lower_bound = stats.q1 - 1.5 * stats.iqr
        upper_bound = stats.q3 + 1.5 * stats.iqr
        return value < lower_bound or value > upper_bound

    # ------------------------------------------------------------------
    # Timestamp Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(ts: Any) -> float:
        """Convert various timestamp formats to Unix epoch float."""
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, datetime):
            return ts.timestamp()
        if isinstance(ts, str):
            # Try ISO format
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(ts, fmt).timestamp()
                except ValueError:
                    continue
            # Try Unix timestamp as string
            try:
                return float(ts)
            except ValueError:
                pass
        return time.time()
