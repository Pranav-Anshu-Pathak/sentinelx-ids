"""
SentinelX IDS - SQLAlchemy ORM Models

Defines all database tables: User, LogEntry, Alert, Rule,
Investigation, and ThreatIntelEntry with proper indexes,
relationships, and enum types.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════

class UserRole(str, enum.Enum):
    """Roles controlling access levels within SentinelX."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class LogSource(str, enum.Enum):
    """Supported log source types."""
    SYSLOG = "syslog"
    WINDOWS = "windows"
    FIREWALL = "firewall"
    WEB = "web"
    SURICATA = "suricata"


class Severity(str, enum.Enum):
    """Severity levels for logs and alerts."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    """Lifecycle status of an alert."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class InvestigationStatus(str, enum.Enum):
    """Status of an investigation."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CLOSED = "closed"


class IndicatorType(str, enum.Enum):
    """Types of threat intelligence indicators."""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class AuditAction(str, enum.Enum):
    """Categories of auditable user actions."""
    # Auth
    LOGIN            = "login"
    LOGOUT           = "logout"
    LOGIN_FAILED     = "login_failed"
    # Alerts
    ALERT_VIEW       = "alert_view"
    ALERT_UPDATE     = "alert_update"
    ALERT_CREATE     = "alert_create"
    ALERT_DELETE     = "alert_delete"
    # Rules
    RULE_CREATE      = "rule_create"
    RULE_UPDATE      = "rule_update"
    RULE_DELETE      = "rule_delete"
    RULE_TOGGLE      = "rule_toggle"
    # Threat Intel
    IOC_CREATE       = "ioc_create"
    IOC_UPDATE       = "ioc_update"
    IOC_DELETE       = "ioc_delete"
    IOC_LOOKUP       = "ioc_lookup"
    IP_BLOCK         = "ip_block"
    IP_UNBLOCK       = "ip_unblock"
    FEED_SYNC        = "feed_sync"
    # Investigations
    INVESTIGATION_CREATE = "investigation_create"
    INVESTIGATION_UPDATE = "investigation_update"
    # Notifications
    NOTIFICATION_TEST    = "notification_test"
    # System
    SETTINGS_VIEW    = "settings_view"
    EXPORT           = "export"
    SYSTEM           = "system"


# ═══════════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════════

class User(Base):
    """Application user account."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.VIEWER
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role.value}>"


class LogEntry(Base):
    """Ingested log event."""

    __tablename__ = "log_entries"
    __table_args__ = (
        Index("ix_log_entries_timestamp", "timestamp"),
        Index("ix_log_entries_severity", "severity"),
        Index("ix_log_entries_source", "source"),
        Index("ix_log_entries_source_ip", "source_ip"),
        Index("ix_log_entries_dest_ip", "dest_ip"),
        Index("ix_log_entries_hostname", "hostname"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    raw_message: Mapped[str] = mapped_column(Text, nullable=False)
    parsed_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[LogSource] = mapped_column(Enum(LogSource), nullable=False, default=LogSource.SYSLOG)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, default=Severity.INFO)
    service: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    event_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<LogEntry id={self.id} source={self.source.value} severity={self.severity.value}>"


class Alert(Base):
    """Security alert generated by detection rules or anomaly detection."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created_at", "created_at"),
        Index("ix_alerts_source_ip", "source_ip"),
        Index("ix_alerts_mitre_technique", "mitre_technique"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), nullable=False, default=AlertStatus.OPEN
    )
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    rule_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("rules.id", ondelete="SET NULL"), nullable=True
    )
    geo_country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    geo_city: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    rule: Mapped[Optional["Rule"]] = relationship("Rule", back_populates="alerts", lazy="selectin")
    investigations: Mapped[List["Investigation"]] = relationship(
        "Investigation", back_populates="alert", cascade="all, delete-orphan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} title={self.title!r} severity={self.severity.value}>"


class Rule(Base):
    """Detection rule that generates alerts when matched."""

    __tablename__ = "rules"
    __table_args__ = (
        Index("ix_rules_category", "category"),
        Index("ix_rules_enabled", "enabled"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    pattern: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    hits: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    yaml_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="rule", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Rule id={self.id} name={self.name!r} enabled={self.enabled}>"


class Investigation(Base):
    """Investigation attached to an alert for deeper analysis."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus), nullable=False, default=InvestigationStatus.OPEN
    )
    analyst: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    alert: Mapped["Alert"] = relationship("Alert", back_populates="investigations", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Investigation id={self.id} alert_id={self.alert_id} status={self.status.value}>"


class ThreatIntelEntry(Base):
    """Threat intelligence indicator (IOC)."""

    __tablename__ = "threat_intel"
    __table_args__ = (
        Index("ix_threat_intel_indicator", "indicator_type", "indicator_value", unique=True),
        Index("ix_threat_intel_threat_score", "threat_score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_type: Mapped[IndicatorType] = mapped_column(
        Enum(IndicatorType), nullable=False
    )
    indicator_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    isp: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    tags: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatIntelEntry id={self.id} type={self.indicator_type.value} "
            f"value={self.indicator_value!r}>"
        )


class AuditLog(Base):
    """Immutable record of every significant user action in SentinelX."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_timestamp",  "timestamp"),
        Index("ix_audit_logs_user",       "username"),
        Index("ix_audit_logs_action",     "action"),
        Index("ix_audit_logs_resource",   "resource_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Who
    user_id:  Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    user_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    # What
    action:        Mapped[AuditAction] = mapped_column(Enum(AuditAction), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(64),  nullable=True)   # alert, rule, ioc …
    resource_id:   Mapped[Optional[str]] = mapped_column(String(128), nullable=True)   # id or value
    description:   Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra:         Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Context
    ip_address:  Mapped[Optional[str]] = mapped_column(String(45),  nullable=True)
    user_agent:  Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    status:      Mapped[str]           = mapped_column(String(16), default="success", nullable=False)  # success | failure

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} user={self.username!r} action={self.action.value}>"
