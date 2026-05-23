"""
SentinelX IDS - Alert Notifier

Dispatches rich, formatted notifications to configured channels:
  • Slack   – Block Kit formatted messages with severity colours
  • Discord – Embeds with fields, severity colour, and footer
  • Email   – HTML email with full alert details (async via thread)

Features:
  • Severity filtering (only notify for alerts above configured threshold)
  • Rate limiting   (same source IP → max 1 notify per 5 minutes)
  • Notification history (in-memory ring buffer, last 200 entries)
  • Test notification (send a dummy alert to verify config)
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import threading
from collections import deque
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Deque, Optional

import httpx

from backend.config import settings

logger = logging.getLogger("sentinelx.alerts")

# ─────────────────────────────────────────────────────────────────────────────
# Notification history  (ring buffer, thread-safe)
# ─────────────────────────────────────────────────────────────────────────────

_HISTORY_SIZE = 200
_history: Deque[dict] = deque(maxlen=_HISTORY_SIZE)
_history_lock = threading.Lock()


def _record(channel: str, status: str, alert_title: str, detail: str = "") -> None:
    with _history_lock:
        _history.appendleft({
            "channel": channel,
            "status": status,          # sent | skipped | error
            "alert_title": alert_title,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


def get_notification_history() -> list[dict]:
    with _history_lock:
        return list(_history)


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter  (per source-IP, 5-minute cooldown)
# ─────────────────────────────────────────────────────────────────────────────

_COOLDOWN_SECONDS = 300          # 5 minutes
_rate_cache: dict[str, float] = {}   # source_ip → last_notified epoch
_rate_lock = threading.Lock()


def _is_rate_limited(source_ip: Optional[str]) -> bool:
    if not source_ip:
        return False
    import time
    now = time.monotonic()
    with _rate_lock:
        last = _rate_cache.get(source_ip, 0.0)
        if now - last < _COOLDOWN_SECONDS:
            return True
        _rate_cache[source_ip] = now
        # Prune old entries every 1 000 entries
        if len(_rate_cache) > 1000:
            cutoff = now - _COOLDOWN_SECONDS
            for k in list(_rate_cache.keys()):
                if _rate_cache[k] < cutoff:
                    del _rate_cache[k]
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Severity ordering  (for threshold filtering)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_COLOURS = {
    "critical": {"slack": "#FF3B5C", "discord": 0xFF3B5C, "html": "#FF3B5C"},
    "high":     {"slack": "#FF6B35", "discord": 0xFF6B35, "html": "#FF6B35"},
    "medium":   {"slack": "#FFAB00", "discord": 0xFFAB00, "html": "#FFAB00"},
    "low":      {"slack": "#00D4FF", "discord": 0x00D4FF, "html": "#00D4FF"},
    "info":     {"slack": "#4A6A9A", "discord": 0x4A6A9A, "html": "#4A6A9A"},
}
_SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}
_MIN_SEVERITY_DEFAULT = "medium"   # notify for medium, high, critical


def _above_threshold(severity: str, min_severity: str = _MIN_SEVERITY_DEFAULT) -> bool:
    return _SEVERITY_ORDER.get(severity.lower(), 0) >= _SEVERITY_ORDER.get(min_severity.lower(), 2)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _format_timestamp(ts: Any = None) -> str:
    if ts is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(ts)


# ─────────────────────────────────────────────────────────────────────────────
# Slack
# ─────────────────────────────────────────────────────────────────────────────

async def _notify_slack(alert: dict) -> None:
    if not settings.SLACK_WEBHOOK_URL:
        return

    sev = alert.get("severity", "medium").lower()
    colour = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["medium"])["slack"]
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")
    title = alert.get("title", "SentinelX Alert")

    # Build Slack Block Kit payload
    fields = []
    if alert.get("source_ip"):
        fields.append({"type": "mrkdwn", "text": f"*Source IP*\n`{alert['source_ip']}`"})
    if alert.get("hostname"):
        fields.append({"type": "mrkdwn", "text": f"*Hostname*\n`{alert['hostname']}`"})
    if alert.get("risk_score") is not None:
        fields.append({"type": "mrkdwn", "text": f"*Risk Score*\n`{alert['risk_score']:.0f} / 100`"})
    if alert.get("mitre_technique"):
        fields.append({"type": "mrkdwn", "text": f"*MITRE*\n`{alert['mitre_technique']}`"})
    if alert.get("id"):
        fields.append({"type": "mrkdwn", "text": f"*Alert ID*\n`#{alert['id']}`"})

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (alert.get("description") or "No description")[:800],
            },
        },
    ]
    if fields:
        blocks.append({"type": "section", "fields": fields[:10]})

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": (
                    f"SentinelX IDS  •  Severity: *{sev.upper()}*  •  "
                    f"{_format_timestamp()}"
                ),
            }
        ],
    })

    payload = {
        "text": f"{emoji} [{sev.upper()}] {title}",   # fallback text
        "attachments": [{"color": colour, "blocks": blocks}],
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
            if resp.status_code == 200:
                _record("slack", "sent", title)
                logger.info("Slack notification sent for alert: %s", title)
            else:
                _record("slack", "error", title, f"HTTP {resp.status_code}: {resp.text[:200]}")
                logger.warning("Slack returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        _record("slack", "error", title, str(exc))
        logger.warning("Slack notification failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Discord
# ─────────────────────────────────────────────────────────────────────────────

async def _notify_discord(alert: dict) -> None:
    if not settings.DISCORD_WEBHOOK_URL:
        return

    sev = alert.get("severity", "medium").lower()
    colour = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["medium"])["discord"]
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")
    title = alert.get("title", "SentinelX Alert")

    embed_fields = []
    if alert.get("source_ip"):
        embed_fields.append({"name": "Source IP", "value": f"`{alert['source_ip']}`", "inline": True})
    if alert.get("hostname"):
        embed_fields.append({"name": "Hostname", "value": f"`{alert['hostname']}`", "inline": True})
    if alert.get("risk_score") is not None:
        embed_fields.append({"name": "Risk Score", "value": f"`{alert['risk_score']:.0f}/100`", "inline": True})
    if alert.get("mitre_technique"):
        embed_fields.append({"name": "MITRE Technique", "value": f"`{alert['mitre_technique']}`", "inline": True})
    if alert.get("mitre_tactic"):
        embed_fields.append({"name": "MITRE Tactic", "value": alert["mitre_tactic"], "inline": True})
    if alert.get("id"):
        embed_fields.append({"name": "Alert ID", "value": f"#{alert['id']}", "inline": True})

    embed = {
        "title": f"{emoji} {title}",
        "description": (alert.get("description") or "No description")[:2000],
        "color": colour,
        "fields": embed_fields,
        "footer": {
            "text": f"SentinelX IDS  •  Severity: {sev.upper()}",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                settings.DISCORD_WEBHOOK_URL,
                json={"embeds": [embed]},
            )
            if resp.status_code in (200, 204):
                _record("discord", "sent", title)
                logger.info("Discord notification sent for alert: %s", title)
            else:
                _record("discord", "error", title, f"HTTP {resp.status_code}: {resp.text[:200]}")
                logger.warning("Discord returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        _record("discord", "error", title, str(exc))
        logger.warning("Discord notification failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Email  (sent in thread to avoid blocking async loop)
# ─────────────────────────────────────────────────────────────────────────────

def _build_html_email(alert: dict) -> str:
    """Build a rich HTML email body for the alert."""
    sev = alert.get("severity", "medium").lower()
    colour = _SEVERITY_COLOURS.get(sev, _SEVERITY_COLOURS["medium"])["html"]
    emoji = _SEVERITY_EMOJI.get(sev, "⚪")
    title = alert.get("title", "SentinelX Alert")

    rows = ""
    details = {
        "Alert ID":        f"#{alert.get('id', 'N/A')}",
        "Severity":        sev.upper(),
        "Risk Score":      f"{alert.get('risk_score', 0):.0f} / 100",
        "Source IP":       alert.get("source_ip") or "—",
        "Destination IP":  alert.get("dest_ip") or "—",
        "Hostname":        alert.get("hostname") or "—",
        "MITRE Technique": alert.get("mitre_technique") or "—",
        "MITRE Tactic":    alert.get("mitre_tactic") or "—",
        "Time":            _format_timestamp(),
    }
    for k, v in details.items():
        rows += f"""
        <tr>
          <td style="padding:8px 12px;font-weight:600;color:#8aa4c8;width:160px;border-bottom:1px solid #1e3050;">{k}</td>
          <td style="padding:8px 12px;font-family:monospace;color:#e2eaf5;border-bottom:1px solid #1e3050;">{v}</td>
        </tr>"""

    description = (alert.get("description") or "No description.")[:2000]

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#060b14;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:32px auto;">
    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#0c1422,#111c2e);padding:24px 32px;border-radius:12px 12px 0 0;border-top:3px solid {colour};">
        <div style="font-size:11px;letter-spacing:4px;color:#4a6a9a;text-transform:uppercase;margin-bottom:6px;">SentinelX IDS — Security Alert</div>
        <div style="font-size:22px;font-weight:700;color:#e2eaf5;">{emoji} {title}</div>
      </td>
    </tr>
    <!-- Severity badge -->
    <tr>
      <td style="background:#0c1422;padding:12px 32px;">
        <span style="display:inline-block;background:{colour}22;color:{colour};border:1px solid {colour}44;
          padding:4px 14px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:2px;">
          {sev.upper()}
        </span>
      </td>
    </tr>
    <!-- Details table -->
    <tr>
      <td style="background:#0c1422;padding:0 32px 16px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #1e3050;">
          {rows}
        </table>
      </td>
    </tr>
    <!-- Description -->
    <tr>
      <td style="background:#0c1422;padding:0 32px 24px;">
        <div style="background:#111c2e;border:1px solid #1e3050;border-radius:8px;padding:16px;">
          <div style="font-size:11px;letter-spacing:2px;color:#4a6a9a;margin-bottom:8px;">DESCRIPTION</div>
          <div style="color:#8aa4c8;font-size:14px;line-height:1.6;">{description}</div>
        </div>
      </td>
    </tr>
    <!-- Footer -->
    <tr>
      <td style="background:#060b14;padding:16px 32px;border-radius:0 0 12px 12px;text-align:center;">
        <div style="font-size:11px;color:#4a6a9a;">Generated by SentinelX IDS • {_format_timestamp()}</div>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _send_email_sync(subject: str, html_body: str, plain_body: str) -> tuple[bool, str]:
    """Synchronous email send — runs in a thread."""
    recipients = settings.alert_email_recipients_list
    if not settings.SMTP_HOST or not recipients:
        return False, "SMTP not configured"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SentinelX] {subject}"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as server:
            server.ehlo()
            if settings.SMTP_TLS:
                server.starttls()
                server.ehlo()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, recipients, msg.as_string())
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


async def _notify_email(alert: dict) -> None:
    recipients = settings.alert_email_recipients_list
    if not settings.SMTP_HOST or not recipients:
        return

    title = alert.get("title", "SentinelX Alert")
    sev = alert.get("severity", "medium").lower()
    html_body = _build_html_email(alert)
    plain_body = (
        f"[SentinelX Alert — {sev.upper()}]\n\n"
        f"Title:    {title}\n"
        f"Source:   {alert.get('source_ip', 'N/A')}\n"
        f"Risk:     {alert.get('risk_score', 0):.0f}/100\n"
        f"MITRE:    {alert.get('mitre_technique', 'N/A')}\n\n"
        f"{alert.get('description', '')[:1000]}\n\n"
        f"-- SentinelX IDS"
    )

    # Run blocking SMTP call in thread pool
    loop = asyncio.get_event_loop()
    ok, detail = await loop.run_in_executor(
        None, _send_email_sync, title, html_body, plain_body
    )
    if ok:
        _record("email", "sent", title)
        logger.info("Email notification sent for alert: %s", title)
    else:
        _record("email", "error", title, detail)
        logger.warning("Email notification failed: %s", detail)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def notify_alert(
    alert_data: dict[str, Any],
    min_severity: str = _MIN_SEVERITY_DEFAULT,
    skip_rate_limit: bool = False,
) -> dict[str, Any]:
    """
    Dispatch alert notifications to all configured channels.

    Args:
        alert_data:      Alert dict (must have title, severity, source_ip, etc.)
        min_severity:    Minimum severity to notify on (default: medium)
        skip_rate_limit: If True, bypass the per-source-IP cooldown (use for tests)

    Returns:
        Dict with dispatched channel list and skip reason (if any).
    """
    title = alert_data.get("title", "SentinelX Alert")
    severity = (alert_data.get("severity") or "medium").lower()
    source_ip = alert_data.get("source_ip")

    # ── Severity threshold check ────────────────────────────────────────────
    if not _above_threshold(severity, min_severity):
        reason = f"severity '{severity}' below threshold '{min_severity}'"
        _record("all", "skipped", title, reason)
        return {"dispatched": [], "skipped": True, "reason": reason}

    # ── Rate limit check ────────────────────────────────────────────────────
    if not skip_rate_limit and _is_rate_limited(source_ip):
        reason = f"rate-limited for source_ip {source_ip}"
        _record("all", "skipped", title, reason)
        return {"dispatched": [], "skipped": True, "reason": reason}

    # ── Dispatch to all configured channels ─────────────────────────────────
    dispatched: list[str] = []
    tasks = []

    if settings.SLACK_WEBHOOK_URL:
        tasks.append(_notify_slack(alert_data))
        dispatched.append("slack")

    if settings.DISCORD_WEBHOOK_URL:
        tasks.append(_notify_discord(alert_data))
        dispatched.append("discord")

    if settings.SMTP_HOST and settings.alert_email_recipients_list:
        tasks.append(_notify_email(alert_data))
        dispatched.append("email")

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    else:
        logger.debug("No notification channels configured — skipping")

    return {"dispatched": dispatched, "skipped": False}


async def send_test_notification(channel: Optional[str] = None) -> dict[str, Any]:
    """
    Send a test notification to verify configuration.
    channel: 'slack' | 'discord' | 'email' | None (all configured)
    """
    test_alert = {
        "id": 9999,
        "title": "🧪 SentinelX Test Notification",
        "description": (
            "This is a test notification from SentinelX IDS. "
            "If you received this, your notification channel is correctly configured."
        ),
        "severity": "high",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.1",
        "hostname": "test-host",
        "risk_score": 75.0,
        "mitre_technique": "T1110",
        "mitre_tactic": "Credential Access",
    }

    dispatched = []

    if channel == "slack" or (channel is None and settings.SLACK_WEBHOOK_URL):
        await _notify_slack(test_alert)
        dispatched.append("slack")

    if channel == "discord" or (channel is None and settings.DISCORD_WEBHOOK_URL):
        await _notify_discord(test_alert)
        dispatched.append("discord")

    if channel == "email" or (channel is None and settings.SMTP_HOST and settings.alert_email_recipients_list):
        await _notify_email(test_alert)
        dispatched.append("email")

    return {
        "status": "sent" if dispatched else "no_channels_configured",
        "dispatched": dispatched,
        "test_alert": test_alert,
    }


def get_notification_config_status() -> dict[str, Any]:
    """Return which notification channels are configured (without exposing secrets)."""
    return {
        "slack": {
            "configured": bool(settings.SLACK_WEBHOOK_URL),
            "channel": "Slack Webhook",
        },
        "discord": {
            "configured": bool(settings.DISCORD_WEBHOOK_URL),
            "channel": "Discord Webhook",
        },
        "email": {
            "configured": bool(settings.SMTP_HOST and settings.alert_email_recipients_list),
            "smtp_host": settings.SMTP_HOST or None,
            "recipients_count": len(settings.alert_email_recipients_list),
        },
        "min_severity": _MIN_SEVERITY_DEFAULT,
        "rate_limit_seconds": _COOLDOWN_SECONDS,
    }
