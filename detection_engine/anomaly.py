"""SentinelX IDS - Anomaly Detector.

Statistical anomaly detection for events using:

- **Z-score** — deviation from the rolling mean/stddev baseline.
- **IQR (Interquartile Range)** — robust outlier detection.
- **Time-of-day analysis** — flags unusual-hour activity.
- **Volume anomaly** — detects bursts that deviate from baseline.
- **Impossible travel** — flags login events where the geographic
  distance vs. time gap is physically impossible.

All baselines are maintained per ``(source, event_type)`` key so that
different log sources and event types are modelled independently.
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger("sentinelx.anomaly")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASELINE_WINDOW: int = 1000          # Max events retained per key
_MIN_BASELINE: int = 30              # Minimum events before scoring
_VOLUME_BUCKET_SECONDS: float = 60.0  # Bucket size for volume analysis
_VOLUME_BUCKETS: int = 60            # ~1 hour of history
_EARTH_RADIUS_KM: float = 6_371.0    # For Haversine
_MAX_TRAVEL_SPEED_KMH: float = 1_000.0  # Realistic max (fast jet)

# Hours considered "off-hours" (UTC)
_OFF_HOURS: frozenset[int] = frozenset(range(0, 6))  # midnight – 05:59 UTC


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _EventRecord:
    """Lightweight event record for baseline tracking."""
    timestamp: float
    hour: int
    source_ip: str
    latitude: float
    longitude: float
    value: float  # generic numeric signal (e.g. bytes, count)


@dataclass(slots=True)
class _Baseline:
    """Rolling baseline for a (source, event_type) key."""
    events: deque[_EventRecord] = field(
        default_factory=lambda: deque(maxlen=_BASELINE_WINDOW)
    )
    hourly_counts: dict[int, int] = field(default_factory=lambda: {h: 0 for h in range(24)})
    volume_buckets: deque[tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=_VOLUME_BUCKETS)
    )
    last_bucket_time: float = 0.0
    current_bucket_count: int = 0
    last_event_by_ip: dict[str, _EventRecord] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Statistical anomaly detector that learns baselines from event streams.

    Usage::

        detector = AnomalyDetector()

        # Learning phase — feed normal events
        for event in normal_events:
            detector.update_baseline(event)

        # Detection phase
        score = detector.calculate_anomaly_score(suspect_event)
        if detector.is_anomalous(suspect_event, threshold=0.7):
            raise Alert(...)
    """

    def __init__(self) -> None:
        # Key: (source, event_type) → _Baseline
        self._baselines: dict[tuple[str, str], _Baseline] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_baseline(self, event: dict[str, Any]) -> None:
        """Record an event to update the rolling baseline.

        Expected event keys::

            source, event_type, source_ip, timestamp (epoch float or datetime),
            metadata.latitude, metadata.longitude, metadata.bytes_sent

        Args:
            event: Structured event dictionary.
        """
        key = self._event_key(event)
        bl = self._baselines.setdefault(key, _Baseline())

        now = self._event_timestamp(event)
        hour = datetime.utcfromtimestamp(now).hour
        source_ip = str(event.get("source_ip", ""))
        metadata = event.get("metadata", {}) or {}
        latitude = float(metadata.get("latitude", 0.0))
        longitude = float(metadata.get("longitude", 0.0))
        value = float(metadata.get("bytes_sent", 0) or metadata.get("value", 0) or 0)

        record = _EventRecord(
            timestamp=now,
            hour=hour,
            source_ip=source_ip,
            latitude=latitude,
            longitude=longitude,
            value=value,
        )

        bl.events.append(record)
        bl.hourly_counts[hour] = bl.hourly_counts.get(hour, 0) + 1

        # Volume bucketing
        self._update_volume_bucket(bl, now)

        # Track last event per IP for impossible-travel
        if source_ip:
            bl.last_event_by_ip[source_ip] = record

    def calculate_anomaly_score(self, event: dict[str, Any]) -> float:
        """Calculate an anomaly score for the given event.

        The score is a float in ``[0.0, 1.0]`` where higher values indicate
        greater anomaly.  The score is a weighted average of:

        - **Time-of-day score** (weight 0.25)
        - **Volume anomaly score** (weight 0.30)
        - **Z-score / IQR score** on numeric value (weight 0.20)
        - **Impossible travel score** (weight 0.25)

        Args:
            event: Structured event dictionary.

        Returns:
            Anomaly score between 0.0 and 1.0.
        """
        key = self._event_key(event)
        bl = self._baselines.get(key)

        # If no baseline exists yet, moderate anomaly (unknown = suspicious)
        if bl is None or len(bl.events) < _MIN_BASELINE:
            return 0.5

        now = self._event_timestamp(event)
        hour = datetime.utcfromtimestamp(now).hour
        source_ip = str(event.get("source_ip", ""))
        metadata = event.get("metadata", {}) or {}
        latitude = float(metadata.get("latitude", 0.0))
        longitude = float(metadata.get("longitude", 0.0))
        value = float(metadata.get("bytes_sent", 0) or metadata.get("value", 0) or 0)

        # --- Time-of-day ---
        time_score = self._time_of_day_score(bl, hour)

        # --- Volume anomaly ---
        volume_score = self._volume_anomaly_score(bl, now)

        # --- Z-score / IQR on value ---
        value_score = self._value_anomaly_score(bl, value)

        # --- Impossible travel ---
        travel_score = self._impossible_travel_score(bl, source_ip, now, latitude, longitude)

        # Weighted average
        total = (
            0.25 * time_score
            + 0.30 * volume_score
            + 0.20 * value_score
            + 0.25 * travel_score
        )

        return max(0.0, min(1.0, total))

    def is_anomalous(self, event: dict[str, Any], threshold: float = 0.7) -> bool:
        """Check if an event exceeds the anomaly threshold.

        Args:
            event: Structured event dictionary.
            threshold: Score threshold (default 0.7).

        Returns:
            ``True`` if the event's anomaly score ≥ *threshold*.
        """
        return self.calculate_anomaly_score(event) >= threshold

    # ------------------------------------------------------------------
    # Scoring components
    # ------------------------------------------------------------------

    @staticmethod
    def _time_of_day_score(bl: _Baseline, hour: int) -> float:
        """Score how unusual the current hour is relative to the baseline.

        Uses the proportion of events seen in this hour vs. the busiest hour.
        Off-hours with zero or very low baseline traffic score highest.
        """
        total_events = sum(bl.hourly_counts.values())
        if total_events == 0:
            return 0.5

        hour_count = bl.hourly_counts.get(hour, 0)
        max_count = max(bl.hourly_counts.values())

        if max_count == 0:
            return 0.5

        # Ratio: 0 = this hour is the most active (normal), 1 = never seen
        ratio = 1.0 - (hour_count / max_count)

        # Amplify if it's an off-hour with very low baseline
        if hour in _OFF_HOURS and hour_count < (total_events / 48):
            ratio = min(1.0, ratio + 0.3)

        return ratio

    @staticmethod
    def _volume_anomaly_score(bl: _Baseline, now: float) -> float:
        """Score whether the current event rate deviates from the baseline.

        Uses z-score over the recent volume buckets.
        """
        if len(bl.volume_buckets) < 5:
            return 0.3

        bucket_counts = [count for _, count in bl.volume_buckets]

        # Add current bucket
        if bl.last_bucket_time > 0 and (now - bl.last_bucket_time) < _VOLUME_BUCKET_SECONDS:
            current = bl.current_bucket_count + 1
        else:
            current = 1

        mean = statistics.mean(bucket_counts)
        stdev = statistics.pstdev(bucket_counts)

        if stdev == 0:
            # All buckets have the same count
            if current > mean * 2:
                return 0.8
            return 0.0

        z = (current - mean) / stdev

        # Map z-score to [0, 1]: z=0 → 0, z>=3 → 1
        score = min(1.0, max(0.0, z / 3.0))
        return score

    @staticmethod
    def _value_anomaly_score(bl: _Baseline, value: float) -> float:
        """Score the numeric value using both z-score and IQR methods.

        Takes the maximum of the two methods for robustness.
        """
        values = [e.value for e in bl.events if e.value > 0]
        if len(values) < _MIN_BASELINE:
            return 0.3

        # --- Z-score ---
        mean = statistics.mean(values)
        stdev = statistics.pstdev(values)
        z_score_val = 0.0
        if stdev > 0:
            z = abs(value - mean) / stdev
            z_score_val = min(1.0, z / 3.0)

        # --- IQR ---
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        q1 = sorted_vals[n // 4]
        q3 = sorted_vals[3 * n // 4]
        iqr = q3 - q1

        iqr_score = 0.0
        if iqr > 0:
            upper_fence = q3 + 1.5 * iqr
            lower_fence = q1 - 1.5 * iqr
            if value > upper_fence:
                excess = (value - upper_fence) / iqr
                iqr_score = min(1.0, excess / 3.0)
            elif value < lower_fence:
                deficit = (lower_fence - value) / iqr
                iqr_score = min(1.0, deficit / 3.0)

        return max(z_score_val, iqr_score)

    @staticmethod
    def _impossible_travel_score(
        bl: _Baseline,
        source_ip: str,
        now: float,
        latitude: float,
        longitude: float,
    ) -> float:
        """Score for impossible travel detection.

        If the same IP was recently seen from a significantly different
        geographic location and the distance/time ratio exceeds
        ``_MAX_TRAVEL_SPEED_KMH``, score is elevated.
        """
        if not source_ip or (latitude == 0.0 and longitude == 0.0):
            return 0.0

        prev = bl.last_event_by_ip.get(source_ip)
        if prev is None:
            return 0.0

        if prev.latitude == 0.0 and prev.longitude == 0.0:
            return 0.0

        time_delta_hours = (now - prev.timestamp) / 3600.0
        if time_delta_hours <= 0:
            return 0.0

        distance_km = _haversine_km(prev.latitude, prev.longitude, latitude, longitude)

        if distance_km < 50:
            # Same city — not suspicious
            return 0.0

        speed_kmh = distance_km / time_delta_hours

        if speed_kmh > _MAX_TRAVEL_SPEED_KMH:
            # Impossible travel — score proportional to excess
            ratio = speed_kmh / _MAX_TRAVEL_SPEED_KMH
            return min(1.0, ratio / 5.0 + 0.5)

        return 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _event_key(event: dict[str, Any]) -> tuple[str, str]:
        """Derive the baseline key from an event."""
        source = str(event.get("source", "unknown"))
        event_type = str(event.get("event_type", "unknown"))
        return (source, event_type)

    @staticmethod
    def _event_timestamp(event: dict[str, Any]) -> float:
        """Extract or compute the event timestamp as epoch float."""
        ts = event.get("timestamp")
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, datetime):
            return ts.timestamp()
        return time.time()

    @staticmethod
    def _update_volume_bucket(bl: _Baseline, now: float) -> None:
        """Update the rolling volume bucket."""
        if bl.last_bucket_time == 0.0:
            bl.last_bucket_time = now
            bl.current_bucket_count = 1
            return

        elapsed = now - bl.last_bucket_time
        if elapsed < _VOLUME_BUCKET_SECONDS:
            bl.current_bucket_count += 1
        else:
            # Finalise current bucket
            bl.volume_buckets.append((bl.last_bucket_time, bl.current_bucket_count))
            # Fill empty intermediate buckets
            skipped = int(elapsed / _VOLUME_BUCKET_SECONDS) - 1
            for _ in range(min(skipped, _VOLUME_BUCKETS)):
                bl.volume_buckets.append((bl.last_bucket_time, 0))
            # Start new bucket
            bl.last_bucket_time = now
            bl.current_bucket_count = 1


# ---------------------------------------------------------------------------
# Haversine formula
# ---------------------------------------------------------------------------

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth.

    Args:
        lat1, lon1: Latitude/longitude of point 1 (degrees).
        lat2, lon2: Latitude/longitude of point 2 (degrees).

    Returns:
        Distance in kilometres.
    """
    lat1_r = math.radians(lat1)
    lat2_r = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return _EARTH_RADIUS_KM * c
