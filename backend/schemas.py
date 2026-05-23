"""
SentinelX IDS - Pydantic v2 Schemas

Request / response schemas for every API endpoint with comprehensive
validation, field examples, and a generic paginated-response wrapper.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ═══════════════════════════════════════════════════════════════════════════
# Shared enums (mirrored from models for schema-level validation)
# ═══════════════════════════════════════════════════════════════════════════

class UserRoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class LogSourceEnum(str, Enum):
    SYSLOG = "syslog"
    WINDOWS = "windows"
    FIREWALL = "firewall"
    WEB = "web"
    SURICATA = "suricata"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatusEnum(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class InvestigationStatusEnum(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CLOSED = "closed"


class IndicatorTypeEnum(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


# ═══════════════════════════════════════════════════════════════════════════
# Generic paginated response
# ═══════════════════════════════════════════════════════════════════════════

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated wrapper for list endpoints."""

    model_config = ConfigDict(from_attributes=True)

    items: List[T]
    total: int = Field(..., description="Total number of matching records", examples=[142])
    page: int = Field(..., description="Current page number (1-indexed)", examples=[1])
    page_size: int = Field(..., description="Items per page", examples=[50])
    total_pages: int = Field(..., description="Total number of pages", examples=[3])


# ═══════════════════════════════════════════════════════════════════════════
# Auth / User schemas
# ═══════════════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    """Schema for creating a new user account."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(
        ..., min_length=3, max_length=64,
        examples=["analyst_jane"],
        description="Unique username",
    )
    email: str = Field(
        ..., max_length=255,
        examples=["jane@sentinelx.io"],
        description="Email address",
    )
    password: str = Field(
        ..., min_length=8, max_length=128,
        examples=["Str0ng!Pass#2024"],
        description="Plain-text password (hashed on server)",
    )
    role: UserRoleEnum = Field(
        default=UserRoleEnum.VIEWER,
        description="User role",
    )


class UserLogin(BaseModel):
    """Schema for user login."""

    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(..., examples=["admin"])
    password: str = Field(..., examples=["admin"])


class UserResponse(BaseModel):
    """Public user profile returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: UserRoleEnum
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    """JWT token response."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    user: UserResponse


# ═══════════════════════════════════════════════════════════════════════════
# Log schemas
# ═══════════════════════════════════════════════════════════════════════════

class LogIngest(BaseModel):
    """Schema for ingesting a single log entry."""

    model_config = ConfigDict(str_strip_whitespace=True)

    raw_message: str = Field(
        ..., min_length=1,
        examples=["May 22 14:32:11 web-srv01 sshd[12345]: Failed password for root from 192.168.1.100 port 22"],
        description="Raw log message text",
    )
    source: LogSourceEnum = Field(
        default=LogSourceEnum.SYSLOG,
        description="Log source type",
    )
    source_ip: Optional[str] = Field(default=None, examples=["192.168.1.100"])
    dest_ip: Optional[str] = Field(default=None, examples=["10.0.0.5"])
    hostname: Optional[str] = Field(default=None, examples=["web-srv01"])
    severity: SeverityEnum = Field(default=SeverityEnum.INFO)
    service: Optional[str] = Field(default=None, examples=["sshd"])
    event_type: Optional[str] = Field(default=None, examples=["authentication_failure"])


class LogBatchIngest(BaseModel):
    """Schema for ingesting multiple log entries at once."""

    logs: List[LogIngest] = Field(
        ..., min_length=1, max_length=1000,
        description="List of log entries (max 1 000 per batch)",
    )


class LogResponse(BaseModel):
    """Log entry returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    raw_message: str
    parsed_message: Optional[str] = None
    source: LogSourceEnum
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    severity: SeverityEnum
    service: Optional[str] = None
    event_type: Optional[str] = None
    created_at: datetime


class LogSearchQuery(BaseModel):
    """Search parameters for full-text log search."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ..., min_length=1, max_length=512,
        examples=["Failed password"],
        description="Search query string",
    )
    source: Optional[LogSourceEnum] = None
    severity: Optional[SeverityEnum] = None
    hostname: Optional[str] = None
    source_ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


# ═══════════════════════════════════════════════════════════════════════════
# Alert schemas
# ═══════════════════════════════════════════════════════════════════════════

class AlertCreate(BaseModel):
    """Schema for creating an alert manually or via detection engine."""

    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(..., min_length=1, max_length=512, examples=["Brute-force SSH detected"])
    description: Optional[str] = Field(default=None, examples=["Multiple failed login attempts from 192.168.1.100"])
    severity: SeverityEnum = Field(default=SeverityEnum.MEDIUM)
    source_ip: Optional[str] = Field(default=None, examples=["192.168.1.100"])
    dest_ip: Optional[str] = Field(default=None, examples=["10.0.0.5"])
    hostname: Optional[str] = Field(default=None, examples=["web-srv01"])
    mitre_technique: Optional[str] = Field(default=None, examples=["T1110.001"])
    mitre_tactic: Optional[str] = Field(default=None, examples=["Credential Access"])
    risk_score: float = Field(default=50.0, ge=0, le=100)
    rule_id: Optional[int] = None
    geo_country: Optional[str] = Field(default=None, examples=["CN"])
    geo_city: Optional[str] = Field(default=None, examples=["Beijing"])


class AlertUpdate(BaseModel):
    """Schema for updating an existing alert."""

    status: Optional[AlertStatusEnum] = None
    assigned_to: Optional[str] = Field(default=None, max_length=64)
    severity: Optional[SeverityEnum] = None
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)


class AlertResponse(BaseModel):
    """Alert returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    severity: SeverityEnum
    status: AlertStatusEnum
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    hostname: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    risk_score: float
    rule_id: Optional[int] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AlertStatsResponse(BaseModel):
    """Aggregated alert statistics."""

    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_source_ips: list[dict[str, Any]] = Field(default_factory=list)
    top_mitre_techniques: list[dict[str, Any]] = Field(default_factory=list)
    recent_24h: int = 0


# ═══════════════════════════════════════════════════════════════════════════
# Rule schemas
# ═══════════════════════════════════════════════════════════════════════════

class RuleCreate(BaseModel):
    """Schema for creating a detection rule."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=256, examples=["SSH Brute Force Detection"])
    description: Optional[str] = Field(default=None, examples=["Detects multiple failed SSH login attempts"])
    category: Optional[str] = Field(default=None, examples=["Authentication"])
    mitre_technique: Optional[str] = Field(default=None, examples=["T1110"])
    severity: SeverityEnum = Field(default=SeverityEnum.MEDIUM)
    pattern: Optional[str] = Field(default=None, examples=["Failed password"])
    enabled: bool = Field(default=True)
    yaml_content: Optional[str] = Field(
        default=None,
        description="Full YAML rule definition (Sigma-style)",
    )


class RuleUpdate(BaseModel):
    """Schema for updating a rule."""

    name: Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = None
    category: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    pattern: Optional[str] = None
    enabled: Optional[bool] = None
    yaml_content: Optional[str] = None


class RuleResponse(BaseModel):
    """Detection rule returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: SeverityEnum
    pattern: Optional[str] = None
    enabled: bool
    hits: int
    yaml_content: Optional[str] = None
    created_at: datetime


# ═══════════════════════════════════════════════════════════════════════════
# Investigation schemas
# ═══════════════════════════════════════════════════════════════════════════

class InvestigationCreate(BaseModel):
    """Schema for creating an investigation on an alert."""

    model_config = ConfigDict(str_strip_whitespace=True)

    alert_id: int = Field(..., description="ID of the alert to investigate")
    title: str = Field(..., min_length=1, max_length=512, examples=["Deep dive on SSH brute-force"])
    notes: Optional[str] = Field(default=None, examples=["Initial triage started"])
    analyst: Optional[str] = Field(default=None, examples=["analyst_jane"])


class InvestigationUpdate(BaseModel):
    """Schema for updating an investigation."""

    title: Optional[str] = Field(default=None, max_length=512)
    notes: Optional[str] = None
    status: Optional[InvestigationStatusEnum] = None
    analyst: Optional[str] = None
    ai_summary: Optional[str] = None


class InvestigationResponse(BaseModel):
    """Investigation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: int
    title: str
    notes: Optional[str] = None
    status: InvestigationStatusEnum
    analyst: Optional[str] = None
    ai_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ═══════════════════════════════════════════════════════════════════════════
# Threat Intel schemas
# ═══════════════════════════════════════════════════════════════════════════

class ThreatIntelCreate(BaseModel):
    """Schema for adding a new IOC."""

    model_config = ConfigDict(str_strip_whitespace=True)

    indicator_type: IndicatorTypeEnum = Field(..., examples=["ip"])
    indicator_value: str = Field(..., min_length=1, max_length=512, examples=["185.220.101.1"])
    threat_score: float = Field(default=0.0, ge=0, le=100, examples=[85.0])
    threat_type: Optional[str] = Field(default=None, examples=["botnet"])
    source: Optional[str] = Field(default=None, examples=["AbuseIPDB"])
    country: Optional[str] = Field(default=None, examples=["RU"])
    isp: Optional[str] = Field(default=None, examples=["Hetzner Online GmbH"])
    tags: Optional[dict[str, Any]] = Field(default=None, examples=[{"malware": True}])


class ThreatIntelResponse(BaseModel):
    """Threat intelligence entry returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_type: IndicatorTypeEnum
    indicator_value: str
    threat_score: float
    threat_type: Optional[str] = None
    source: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    tags: Optional[dict[str, Any]] = None
    first_seen: datetime
    last_seen: datetime


class IPLookupRequest(BaseModel):
    """Request body for IP lookup."""

    ip: str = Field(..., examples=["185.220.101.1"], description="IP address to look up")


class IPLookupResponse(BaseModel):
    """Combined IP lookup result from local DB and external APIs."""

    ip: str
    local_records: List[ThreatIntelResponse] = Field(default_factory=list)
    external_data: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0, le=100)
    is_known_threat: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# Health / Metrics
# ═══════════════════════════════════════════════════════════════════════════

class HealthResponse(BaseModel):
    """System health status."""

    status: str = Field(default="healthy", examples=["healthy"])
    version: str = Field(default="1.0.0")
    uptime_seconds: float = Field(default=0.0)
    database: str = Field(default="connected", examples=["connected"])
    demo_mode: bool = False
    timestamp: datetime


class MetricsResponse(BaseModel):
    """Real-time system metrics."""

    events_per_second: float = 0.0
    total_logs: int = 0
    total_alerts: int = 0
    active_rules: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    timestamp: datetime


# ═══════════════════════════════════════════════════════════════════════════
# Search / NLP
# ═══════════════════════════════════════════════════════════════════════════

class NLPSearchQuery(BaseModel):
    """Natural language search query."""

    query: str = Field(
        ..., min_length=1, max_length=1024,
        examples=["Show me all brute force attacks from China in the last 24 hours"],
    )


class NLPSearchResponse(BaseModel):
    """Response from the NLP search engine."""

    original_query: str
    interpreted_query: str = Field(
        ..., description="How the NLP engine interpreted the query"
    )
    filters_applied: dict[str, Any] = Field(default_factory=dict)
    results: List[Any] = Field(default_factory=list)
    total: int = 0


class SearchSuggestion(BaseModel):
    """Pre-built search suggestion."""

    label: str
    query: str
    category: str
