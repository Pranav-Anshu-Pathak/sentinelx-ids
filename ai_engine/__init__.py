"""SentinelX IDS - AI Engine Package.

Provides AI-powered analysis including SOC copilot, NLP query parsing,
anomaly scoring, and optional LLM integration for enhanced threat analysis.
"""

from ai_engine.copilot import SOCCopilot
from ai_engine.nlp_query import NLPQueryParser
from ai_engine.anomaly_scorer import AnomalyScorer
from ai_engine.llm_integration import LLMClient

__all__ = [
    "SOCCopilot",
    "NLPQueryParser",
    "AnomalyScorer",
    "LLMClient",
]
