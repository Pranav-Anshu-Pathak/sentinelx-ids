"""SentinelX IDS - LLM Integration Client.

Optional integration with external LLM providers (OpenAI, Anthropic, Gemini).
Falls back to the local SOC Copilot rule-based analysis when no API key is
configured, ensuring the system always works without external dependencies.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("sentinelx.llm")


class LLMProvider(str, Enum):
    """Supported LLM provider backends."""
    LOCAL = "local"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


@dataclass
class RateLimiter:
    """Simple token-bucket rate limiter for API calls."""

    max_requests: int = 20
    window_seconds: int = 60
    _timestamps: list[float] = field(default_factory=list)

    def acquire(self) -> bool:
        """Try to acquire a rate limit slot.

        Returns:
            True if the request is allowed, False if rate limited.
        """
        now = time.time()
        # Remove timestamps outside the current window
        self._timestamps = [
            ts for ts in self._timestamps
            if now - ts < self.window_seconds
        ]
        if len(self._timestamps) >= self.max_requests:
            return False
        self._timestamps.append(now)
        return True

    @property
    def remaining(self) -> int:
        """Number of remaining requests in the current window."""
        now = time.time()
        self._timestamps = [
            ts for ts in self._timestamps
            if now - ts < self.window_seconds
        ]
        return max(0, self.max_requests - len(self._timestamps))

    @property
    def reset_in(self) -> float:
        """Seconds until the oldest request exits the window."""
        if not self._timestamps:
            return 0.0
        now = time.time()
        oldest = min(self._timestamps)
        return max(0.0, self.window_seconds - (now - oldest))


@dataclass
class LLMResponse:
    """Wrapper for LLM API responses."""

    content: str
    provider: str
    model: str
    tokens_used: int = 0
    latency_ms: float = 0.0
    fallback_used: bool = False


class LLMClient:
    """Unified client for LLM providers with automatic local fallback.

    Usage:
        client = LLMClient()  # defaults to local copilot
        result = client.analyze("Analyze this SSH brute force alert...")

    The client automatically falls back to the local rule-based copilot
    when no API key is configured or when external API calls fail.
    """

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        max_requests_per_minute: int = 20,
    ) -> None:
        self._provider = LLMProvider(
            provider or os.getenv("LLM_PROVIDER", "local")
        )
        self._api_key = api_key or self._resolve_api_key()
        self._model = model or self._default_model()
        self._rate_limiter = RateLimiter(
            max_requests=max_requests_per_minute,
            window_seconds=60,
        )
        self._copilot: Any = None  # Lazy-loaded SOCCopilot

        # Validate configuration
        if self._provider != LLMProvider.LOCAL and not self._api_key:
            logger.warning(
                "No API key configured for provider '%s'. "
                "Falling back to local copilot.",
                self._provider.value,
            )
            self._provider = LLMProvider.LOCAL

    def analyze(self, prompt: str, context: dict[str, Any] | None = None) -> str:
        """Analyze a prompt using the configured LLM provider.

        Args:
            prompt: The analysis prompt or question.
            context: Optional context data to include.

        Returns:
            Analysis result string.
        """
        if self._provider == LLMProvider.LOCAL:
            return self._local_analyze(prompt, context)

        # Check rate limit
        if not self._rate_limiter.acquire():
            logger.warning(
                "Rate limit exceeded (%d/%d). Falling back to local copilot.",
                self._rate_limiter.max_requests,
                self._rate_limiter.window_seconds,
            )
            return self._local_analyze(prompt, context)

        try:
            start = time.time()

            if self._provider == LLMProvider.OPENAI:
                result = self._call_openai(prompt, context)
            elif self._provider == LLMProvider.ANTHROPIC:
                result = self._call_anthropic(prompt, context)
            elif self._provider == LLMProvider.GEMINI:
                result = self._call_gemini(prompt, context)
            else:
                return self._local_analyze(prompt, context)

            latency = (time.time() - start) * 1000
            logger.info(
                "LLM response from %s (%.0fms, model=%s)",
                self._provider.value,
                latency,
                self._model,
            )
            return result

        except Exception as exc:
            logger.error(
                "LLM API error with provider '%s': %s. Falling back to local.",
                self._provider.value,
                exc,
            )
            return self._local_analyze(prompt, context)

    def get_response(self, prompt: str, context: dict[str, Any] | None = None) -> LLMResponse:
        """Get a structured LLM response with metadata.

        Args:
            prompt: The analysis prompt.
            context: Optional context data.

        Returns:
            LLMResponse with content and metadata.
        """
        start = time.time()
        content = self.analyze(prompt, context)
        latency = (time.time() - start) * 1000

        return LLMResponse(
            content=content,
            provider=self._provider.value,
            model=self._model,
            latency_ms=round(latency, 2),
            fallback_used=self._provider == LLMProvider.LOCAL,
        )

    @property
    def provider(self) -> str:
        """Return the currently active provider name."""
        return self._provider.value

    @property
    def is_local(self) -> bool:
        """Check if using the local copilot."""
        return self._provider == LLMProvider.LOCAL

    @property
    def rate_limit_remaining(self) -> int:
        """Number of remaining API requests in the current window."""
        return self._rate_limiter.remaining

    # ------------------------------------------------------------------
    # Provider-specific API Calls
    # ------------------------------------------------------------------

    def _call_openai(self, prompt: str, context: dict[str, Any] | None) -> str:
        """Call the OpenAI API (requires 'openai' package)."""
        try:
            import openai
        except ImportError:
            logger.error("openai package not installed. Install with: pip install openai")
            return self._local_analyze(prompt, context)

        client = openai.OpenAI(api_key=self._api_key)
        system_msg = self._build_system_prompt(context)

        response = client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1500,
            temperature=0.3,
        )
        content = response.choices[0].message.content
        return content if content else self._local_analyze(prompt, context)

    def _call_anthropic(self, prompt: str, context: dict[str, Any] | None) -> str:
        """Call the Anthropic API (requires 'anthropic' package)."""
        try:
            import anthropic
        except ImportError:
            logger.error("anthropic package not installed. Install with: pip install anthropic")
            return self._local_analyze(prompt, context)

        client = anthropic.Anthropic(api_key=self._api_key)
        system_msg = self._build_system_prompt(context)

        response = client.messages.create(
            model=self._model,
            max_tokens=1500,
            system=system_msg,
            messages=[
                {"role": "user", "content": prompt},
            ],
        )
        if response.content and len(response.content) > 0:
            return response.content[0].text
        return self._local_analyze(prompt, context)

    def _call_gemini(self, prompt: str, context: dict[str, Any] | None) -> str:
        """Call the Google Gemini API (requires 'google-genai' package)."""
        try:
            from google import genai
        except ImportError:
            logger.error(
                "google-genai package not installed. Install with: pip install google-genai"
            )
            return self._local_analyze(prompt, context)

        client = genai.Client(api_key=self._api_key)
        system_msg = self._build_system_prompt(context)
        full_prompt = f"{system_msg}\n\n{prompt}"

        response = client.models.generate_content(
            model=self._model,
            contents=full_prompt,
        )
        if response.text:
            return response.text
        return self._local_analyze(prompt, context)

    # ------------------------------------------------------------------
    # Local Fallback
    # ------------------------------------------------------------------

    def _local_analyze(self, prompt: str, context: dict[str, Any] | None) -> str:
        """Analyze using the local rule-based SOC Copilot."""
        if self._copilot is None:
            from ai_engine.copilot import SOCCopilot
            self._copilot = SOCCopilot()

        # Try to determine if the prompt is asking about a specific alert
        if context and "alert" in context:
            return self._copilot.analyze_alert(context["alert"])

        # Try to answer as a query
        return self._copilot.answer_query(prompt, context or {})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_api_key(self) -> str | None:
        """Resolve the API key from environment variables."""
        key_map: dict[LLMProvider, str] = {
            LLMProvider.OPENAI: "OPENAI_API_KEY",
            LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
            LLMProvider.GEMINI: "GEMINI_API_KEY",
        }
        env_var = key_map.get(self._provider)
        if env_var:
            return os.getenv(env_var)
        return None

    def _default_model(self) -> str:
        """Return the default model for the configured provider."""
        model_map: dict[LLMProvider, str] = {
            LLMProvider.LOCAL: "rule-based-v1",
            LLMProvider.OPENAI: "gpt-4o-mini",
            LLMProvider.ANTHROPIC: "claude-sonnet-4-20250514",
            LLMProvider.GEMINI: "gemini-2.0-flash",
        }
        return model_map.get(self._provider, "unknown")

    @staticmethod
    def _build_system_prompt(context: dict[str, Any] | None) -> str:
        """Build a system prompt for the LLM with optional context."""
        base = (
            "You are a SOC (Security Operations Center) analyst AI assistant "
            "for the SentinelX IDS platform. You analyze security alerts, "
            "explain attack techniques, and provide remediation recommendations. "
            "Be concise, technical, and actionable. Reference MITRE ATT&CK "
            "framework when applicable."
        )

        if context:
            context_str = json.dumps(context, indent=2, default=str)
            base += f"\n\nCurrent context:\n```json\n{context_str}\n```"

        return base
