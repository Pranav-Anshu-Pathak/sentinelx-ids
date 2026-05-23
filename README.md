# 🛡️ SentinelX IDS

> An AI-powered, full-stack Intrusion Detection System with real-time alerting, threat intelligence, audit logging, and a beautiful React dashboard.

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Detection Engine** | 8 built-in YAML rules (brute force, port scan, lateral movement, reverse shell, data exfiltration, persistence, privilege escalation, PowerShell) |
| 📊 **Live Dashboard** | Real-time WebSocket feed, severity charts, top source IPs, MITRE heatmap |
| 🚨 **Alert Management** | Paginated alerts with MITRE ATT&CK mapping, status workflow, risk scoring |
| 📜 **Log Viewer** | Live log stream from 5 parsers: Syslog, Windows, Firewall, Web, Suricata |
| 🌐 **Threat Intelligence** | IOC database with 5 auto-synced open-source feeds (Feodo, ET, CINS, URLhaus, ThreatFox), IP/domain/hash enrichment, GeoIP |
| 🤖 **AI Copilot** | SOC analyst assistant — alert analysis, remediation steps, attack explanation (supports OpenAI, Anthropic, Gemini, local LLM) |
| 🔔 **Alert Notifications** | Slack (Block Kit), Discord (embeds), Email (HTML) with severity filtering and rate limiting |
| 📋 **Audit Log** | Immutable trail of every user action — login, alert updates, IP blocks, IOC changes, and more |
| 🔐 **JWT Auth** | Role-based access control: Admin / Analyst / Viewer |
| 🏥 **System Health** | Real-time CPU, memory, disk, and service status |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **Node.js 18+**

### 1. Clone & setup

```bash
git clone https://github.com/pranav-anshu-pathak/sentinelx-ids.git
cd sentinelx-ids
```

### 2. Backend

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env

# Start backend
python -m backend.main
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

### 4. Open the app

| Service | URL |
|---------|-----|
| **Dashboard UI** | http://localhost:5173 |
| **API** | http://localhost:8000 |
| **API Docs** | http://localhost:8000/docs |

### Demo Login

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `sentinelx` |

---

## ⚙️ Configuration

Copy `.env.example` to `.env` and configure:

```env
# Demo mode — generates synthetic security events automatically
DEMO_MODE=true

# Alert Notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_HOST=smtp.gmail.com
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=team@yourcompany.com

# Threat Intelligence API Keys (optional — enhances scoring)
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=

# AI / LLM (optional)
LLM_PROVIDER=local        # or openai / anthropic / gemini
OPENAI_API_KEY=
```

---

## 🏗️ Architecture

```
sentinelx-ids/
├── backend/              # FastAPI app — 61 REST endpoints
│   ├── routes/           # alert, auth, rule, intel, audit, notification...
│   ├── models.py         # SQLAlchemy ORM (7 tables)
│   ├── pipeline.py       # Event → alert → notify pipeline
│   └── audit.py          # Immutable audit logger
├── frontend/             # React 18 + Vite + Framer Motion
│   └── src/pages/        # 10 pages: Dashboard, Alerts, Logs, Rules,
│                         #   Threat Intel, Investigations, Audit Log,
│                         #   Settings, Health, Login
├── detection_engine/     # YAML rule matching (Sigma-like)
├── threat_intel/         # IOC feeds, GeoIP, enrichment, scoring
├── alerts/               # Slack / Discord / Email notifier
├── ai_engine/            # LLM copilot integration
├── parsers/              # Syslog, Windows, Firewall, Web, Suricata
├── collectors/           # Demo log generator + file watcher
└── websocket/            # Real-time event broadcasting
```

---

## 🔌 API Reference

Full interactive docs available at **http://localhost:8000/docs**

Key endpoint groups:

| Prefix | Description |
|--------|-------------|
| `/api/auth` | Login, register, user profile |
| `/api/alerts` | CRUD + stats + filters |
| `/api/logs` | Log search + stream |
| `/api/rules` | Detection rule management |
| `/api/intel` | Threat intel lookup, IOC database, feeds, GeoIP |
| `/api/audit` | Audit log query + statistics |
| `/api/notifications` | Channel config, test, history |
| `/api/copilot` | AI chat + alert analysis |
| `/api/dashboard` | Aggregated dashboard stats |
| `/api/health` | System health metrics |

---

## 🧰 Tech Stack

**Backend:** Python 3.12 · FastAPI · SQLAlchemy (async) · SQLite · aiosqlite · JWT · bcrypt · httpx

**Frontend:** React 18 · Vite · Framer Motion · Recharts · Lucide Icons · React Router

**Detection:** YAML rules · Regex + keyword matching · Anomaly scoring

**Integrations:** Slack · Discord · SMTP · AbuseIPDB · VirusTotal · ip-api.com (GeoIP) · OpenAI / Anthropic / Gemini

---

## 📄 License

MIT — free to use, modify, and distribute.
