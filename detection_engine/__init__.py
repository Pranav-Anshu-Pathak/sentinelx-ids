"""SentinelX IDS - Detection Engine Package.

Provides core detection capabilities including rule-based matching,
event correlation, and anomaly detection for intrusion detection.
"""

from detection_engine.engine import DetectionEngine, Alert
from detection_engine.correlator import EventCorrelator, CorrelationAlert
from detection_engine.anomaly import AnomalyDetector
from detection_engine.rule_loader import RuleLoader, Rule

__all__ = [
    "DetectionEngine",
    "Alert",
    "EventCorrelator",
    "CorrelationAlert",
    "AnomalyDetector",
    "RuleLoader",
    "Rule",
]
