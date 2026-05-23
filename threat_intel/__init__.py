"""
SentinelX IDS - Threat Intelligence Package

Exports:
  - ThreatIntelEngine functions (enrich_ip, enrich_domain, enrich_hash, get_intel_stats)
  - FeedManager (sync_all_feeds, sync_feed, get_feed_statuses)
  - GeoIP (lookup_single, lookup_batch, GeoInfo)
  - Scorer (ThreatVerdict, score_ip, score_domain, score_hash)
"""

from threat_intel.engine import (
    enrich_domain,
    enrich_hash,
    enrich_ip,
    get_intel_stats,
)
from threat_intel.feeds import (
    get_feed_statuses,
    sync_all_feeds,
    sync_feed,
)
from threat_intel.geo import GeoInfo, lookup_batch, lookup_single
from threat_intel.scorer import ThreatVerdict, score_domain, score_hash, score_ip

__all__ = [
    # Engine
    "enrich_ip",
    "enrich_domain",
    "enrich_hash",
    "get_intel_stats",
    # Feeds
    "sync_all_feeds",
    "sync_feed",
    "get_feed_statuses",
    # Geo
    "GeoInfo",
    "lookup_single",
    "lookup_batch",
    # Scorer
    "ThreatVerdict",
    "score_ip",
    "score_domain",
    "score_hash",
]
