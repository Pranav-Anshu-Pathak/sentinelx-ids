"""
SentinelX IDS - Application Configuration

Pydantic Settings class that loads all configuration from environment
variables and .env file. Provides sensible defaults for development
and demo mode operation.
"""

from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the SentinelX IDS backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────
    APP_NAME: str = Field(default="SentinelX IDS", description="Application display name")
    APP_VERSION: str = Field(default="1.0.0", description="Application version")
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    DEMO_MODE: bool = Field(default=True, description="Enable demo mode with simulated data")

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./sentinelx.db",
        description="Async SQLAlchemy database URL",
    )

    # ── Security ─────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="sentinelx-super-secret-key-change-in-production-2024",
        description="JWT signing secret – MUST change in production",
    )
    ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=1440, description="JWT token TTL in minutes (default 24h)"
    )

    # ── Server ───────────────────────────────────────────────────────────
    HOST: str = Field(default="0.0.0.0", description="Bind host")
    PORT: int = Field(default=8000, description="Bind port")
    WS_PORT: int = Field(default=8001, description="WebSocket server port")
    SYSLOG_PORT: int = Field(default=1514, description="Syslog UDP listener port")

    # ── CORS ─────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:5173,http://localhost:8080",
        description="Comma-separated allowed CORS origins",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    # ── AI / LLM ─────────────────────────────────────────────────────────
    LLM_PROVIDER: str = Field(
        default="local",
        description="LLM provider: local, openai, anthropic, gemini",
    )
    OPENAI_API_KEY: str = Field(default="", description="OpenAI API key")
    ANTHROPIC_API_KEY: str = Field(default="", description="Anthropic API key")
    GEMINI_API_KEY: str = Field(default="", description="Google Gemini API key")
    GROQ_API_KEY: str = Field(default="", description="Groq API key (reserved)")

    def resolve_llm_api_key(self) -> str:
        """Return API key for the active LLM provider."""
        keys = {
            "openai": self.OPENAI_API_KEY,
            "anthropic": self.ANTHROPIC_API_KEY,
            "gemini": self.GEMINI_API_KEY,
        }
        return keys.get(self.LLM_PROVIDER.lower(), "")

    # ── API Keys / Integrations ──────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = Field(default="", description="VirusTotal API key")
    ABUSEIPDB_API_KEY: str = Field(default="", description="AbuseIPDB API key")

    # ── Notification Webhooks ────────────────────────────────────────────
    SLACK_WEBHOOK_URL: str = Field(default="", description="Slack incoming webhook URL")
    DISCORD_WEBHOOK_URL: str = Field(default="", description="Discord webhook URL")

    # ── Email / SMTP ─────────────────────────────────────────────────────
    SMTP_HOST: str = Field(default="", description="SMTP server hostname")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: str = Field(default="", description="SMTP username")
    SMTP_PASSWORD: str = Field(default="", description="SMTP password")
    SMTP_FROM: str = Field(default="sentinelx@example.com", description="From address for alerts")
    SMTP_TLS: bool = Field(default=True, description="Use TLS for SMTP")
    ALERT_EMAIL_RECIPIENTS: str = Field(
        default="", description="Comma-separated alert email recipients"
    )

    @property
    def alert_email_recipients_list(self) -> List[str]:
        """Parse comma-separated email recipients into a list."""
        if not self.ALERT_EMAIL_RECIPIENTS:
            return []
        return [r.strip() for r in self.ALERT_EMAIL_RECIPIENTS.split(",") if r.strip()]

    # ── Collector Paths ──────────────────────────────────────────────────
    WATCH_LOG_PATHS: str = Field(
        default="",
        description="Comma-separated file paths to watch for log ingestion",
    )

    @property
    def watch_log_paths_list(self) -> List[Path]:
        """Parse comma-separated log paths into a list of Path objects."""
        if not self.WATCH_LOG_PATHS:
            return []
        return [Path(p.strip()) for p in self.WATCH_LOG_PATHS.split(",") if p.strip()]

    # ── Demo Simulation ──────────────────────────────────────────────────
    SIM_INTERVAL_MIN: float = Field(
        default=2.0, description="Minimum seconds between simulated log events"
    )
    SIM_INTERVAL_MAX: float = Field(
        default=5.0, description="Maximum seconds between simulated log events"
    )

    # ── Validators ───────────────────────────────────────────────────────
    @field_validator("PORT", "WS_PORT", "SYSLOG_PORT", "SMTP_PORT", mode="before")
    @classmethod
    def validate_port(cls, v: int | str) -> int:
        port = int(v)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {port}")
        return port


# ── Singleton ────────────────────────────────────────────────────────────
settings = Settings()
