<div align="center">

# 🛡️ PRAHARI

### *AI-Powered Privileged Access & Insider Threat Detection Platform*

**FinSpark'26 — Bank of Maharashtra | Problem Statement 1**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-4.1-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768_%7C_ML--DSA--65-8B5CF6?style=for-the-badge)](#-post-quantum-cryptography-pqc)

---

*Prahari (प्रहरी — "The Sentinel") watches every privileged user in real time, scores their behaviour using AI + rule engines, responds adaptively, and protects credentials & audit logs with post-quantum cryptography.*

</div>

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Our Solution](#-our-solution)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Demo Walkthrough](#-demo-walkthrough)
- [Detection Engine Deep Dive](#-detection-engine-deep-dive)
- [Post-Quantum Cryptography (PQC)](#-post-quantum-cryptography-pqc)
- [API Reference](#-api-reference)
- [Testing](#-testing)
- [Team](#-team)

---

## 🔍 Problem Statement

> **Privileged Access Abuse & Insider Threat Detection for Banking Systems**

Banks entrust privileged users — DBAs, sysadmins, contractors, vendors — with elevated access to critical systems like core banking databases, payment gateways, and SWIFT terminals. These insiders pose one of the **most dangerous and hardest-to-detect threats** in cybersecurity:

| Insider Type | Description | Example |
|---|---|---|
| **🔴 Malicious** | Intentional data theft or sabotage | A dormant vendor account reactivated to mass-export customer records at 2 AM |
| **🟡 Negligent** | Well-meaning but risky behaviour | An employee accessing sensitive data from an unmanaged personal device |
| **🟠 Compromised** | Hijacked credentials / account takeover | A login from an unrecognized location + device with rapid-fire automated actions |

Traditional SIEM tools detect only **known** patterns. Prahari goes further — combining deterministic rules with **unsupervised AI** to catch what no rulebook anticipated.

---

## 💡 Our Solution

**Prahari** is a full-stack, real-time insider-threat detection and privileged access management (PAM) platform purpose-built for banking environments. It operates on three core pillars:

```
┌─────────────────────────────────────────────────────────────────┐
│                      PRAHARI PLATFORM                           │
├──────────────────┬──────────────────┬───────────────────────────┤
│   🧠 DETECT      │   ⚡ RESPOND      │   🔐 PROTECT              │
│                  │                  │                           │
│ • Rule Engine    │ • Allow          │ • PQC Vault (ML-KEM-768)  │
│ • UEBA (AI/ML)  │ • Step-up MFA    │ • Signed Audit (ML-DSA-65)│
│ • Risk Scoring   │ • Maker-Checker  │ • JIT Access Control      │
│ • Peer Analysis  │ • Auto-Block     │ • Session Recording (PAM) │
└──────────────────┴──────────────────┴───────────────────────────┘
```

---

## ✨ Key Features

### 🧠 AI-Powered Detection
- **Rule Engine** — 10+ deterministic rules across all three insider categories (malicious, negligent, compromised), each carrying weighted scores and type tags
- **UEBA (User & Entity Behaviour Analytics)** — IsolationForest-based unsupervised anomaly detection trained on 14 days of baseline history, with per-user behavioural profiling (usual hours, devices, locations, data volumes)
- **Composite Risk Scoring** — Rules (max 80 pts) + UEBA anomaly (25% weight) + peer deviation bonus, producing a unified 0–100 risk score per session

### ⚡ Adaptive Real-Time Response
| Risk Score | Action | Description |
|:---:|---|---|
| **0 – 39** | ✅ `ALLOW` | Normal activity, no intervention |
| **40 – 69** | 🔑 `STEP_UP_MFA` | Challenge the user with a second factor |
| **70 – 84** | 👥 `MAKER_CHECKER` | Hold for a second officer's approval |
| **85 – 100** | 🚫 `BLOCK` | Immediately terminate the session |

> **Smart Nuance:** Negligent insiders are *never* auto-blocked — they're capped at `MAKER_CHECKER` review, because negligence is a control failure to fix with a human review, not an attack to hard-block.

### 🔐 Privileged Access Management (PAM)
- **Session Recording** — Every privileged command is logged with realistic shell/SQL transcripts for replay
- **Credential Vault** — Secrets encrypted with AES-256-GCM under ML-KEM-768 (post-quantum safe); risk-gated checkout with auto-expiring leases
- **Just-in-Time (JIT) Access** — Zero standing privilege. Employees request time-boxed elevation with justification → SOC approves/denies → auto-expires
- **Access Review** — PAM dashboard flags dormant accounts, expired vendor access, and high-risk permissions

### 🏦 Banking Operations Layer
- **Core Banking Simulation** — Real customer accounts, balances, transfers (NEFT/RTGS/IMPS/UPI)
- **Maker-Checker Workflow** — Dual-approval for high-value/suspicious transactions
- **Fraud Detection** — Transfers flagged by the risk engine are held, requiring SOC resolution

### 🛡️ Post-Quantum Cryptography
- **ML-KEM-768 (FIPS 203)** — Quantum-safe key encapsulation for vault credential encryption
- **ML-DSA-65 (FIPS 204)** — Quantum-safe digital signatures for tamper-evident audit logs
- **Hash-Chained Audit Log** — Each entry hashes over the previous, creating an unbreakable chain; every hash is then ML-DSA signed

### 📊 SOC Dashboard (Real-Time)
- **Live Session Monitor** — WebSocket-powered, updates as events arrive
- **Risk Heatmap & Trend Charts** — Recharts-powered visualizations
- **Alert Feed** — Filterable by severity (CRITICAL / WARNING / INFO)
- **Session Drill-down** — Full event timeline, command replay, UEBA model insights, and feature breakdowns
- **JIT Grant Manager** — Approve/deny elevation requests directly from the console

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (React + Vite + Tailwind)            │
│  ┌────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────────────┐  │
│  │ SOC Console│  │Employee Portal│  │ Login Page │  │ Bank Dashboard │  │
│  └─────┬──────┘  └──────┬───────┘  └─────┬──────┘  └───────┬────────┘  │
│        │                │                │                  │           │
│        └────────────────┴────────┬───────┴──────────────────┘           │
│                                  │ WebSocket + REST API                 │
└──────────────────────────────────┼──────────────────────────────────────┘
                                   │
┌──────────────────────────────────┼──────────────────────────────────────┐
│                          BACKEND (FastAPI + Uvicorn)                    │
│                                  │                                      │
│  ┌───────────────────────────────┼───────────────────────────────────┐  │
│  │                        API Layer (routes.py + ws.py)               │  │
│  └───────────────────────────────┼───────────────────────────────────┘  │
│                                  │                                      │
│  ┌──────────────┐  ┌─────────────┴──────────────┐  ┌─────────────────┐ │
│  │  Detection   │  │    Security & Crypto        │  │   Simulator     │ │
│  │  ┌────────┐  │  │  ┌───────┐  ┌───────────┐  │  │  ┌──────────┐  │ │
│  │  │ Rules  │  │  │  │ Vault │  │ PQC       │  │  │  │ Normal   │  │ │
│  │  │ Engine │  │  │  │(AES+  │  │(ML-KEM-768│  │  │  │ Day Sim  │  │ │
│  │  ├────────┤  │  │  │ML-KEM)│  │ ML-DSA-65)│  │  │  ├──────────┤  │ │
│  │  │ UEBA   │  │  │  ├───────┤  └───────────┘  │  │  │ Attack   │  │ │
│  │  │(IsoFor)│  │  │  │ Audit │                  │  │  │ Scenario │  │ │
│  │  ├────────┤  │  │  │(Chain │                  │  │  └──────────┘  │ │
│  │  │ Risk   │  │  │  │+Sign) │                  │  │                │ │
│  │  │Scoring │  │  │  ├───────┤                  │  │                │ │
│  │  ├────────┤  │  │  │  Auth │                  │  │                │ │
│  │  │Adaptive│  │  │  │(JWT)  │                  │  │                │ │
│  │  │Response│  │  │  └───────┘                  │  │                │ │
│  │  └────────┘  │  └────────────────────────────┘  └─────────────────┘ │
│  └──────────────┘                                                       │
│                                                                         │
│  ┌────────────────────────┐  ┌───────────────────────────────────────┐  │
│  │  Data Models (ORM)     │  │  Banking Layer                        │  │
│  │  User, Session, Event, │  │  Accounts, Transactions,              │  │
│  │  Alert, AuditLog,      │  │  Maker-Checker, PAM                   │  │
│  │  VaultItem, JitGrant   │  │                                       │  │
│  └───────────┬────────────┘  └───────────────────────────────────────┘  │
│              │                                                          │
│  ┌───────────┴────────────┐                                             │
│  │   SQLite (prahari.db)  │                                             │
│  └────────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend** | Python 3.12+, FastAPI, Uvicorn | High-performance async API server |
| **Frontend** | React 19, Vite 7, Tailwind CSS 4, Recharts | Real-time SOC dashboard & employee portal |
| **Database** | SQLite + SQLAlchemy ORM | Zero-config relational store (demo-ready) |
| **AI / ML** | scikit-learn (IsolationForest) | Unsupervised behavioural anomaly detection |
| **Cryptography** | ML-KEM-768 (Kyber), ML-DSA-65 (Dilithium), AES-256-GCM | NIST FIPS 203/204 post-quantum algorithms |
| **Real-time** | WebSocket (FastAPI native) | Live event streaming to SOC console |
| **Auth** | JWT (HS256) | Token-based session management |
| **Testing** | pytest, httpx | Comprehensive API & integration test suite |
| **Deployment** | Docker, Docker Compose | One-command containerized deployment |

---

## 📁 Project Structure

```
Prahari/
├── app/                          # FastAPI backend
│   ├── main.py                   # Application entrypoint & lifespan
│   ├── config.py                 # Pydantic settings (env-configurable)
│   ├── bank.py                   # Core banking simulation layer
│   ├── jit.py                    # Just-in-time privilege elevation
│   ├── pam.py                    # PAM: session recording + access review
│   ├── api/
│   │   ├── routes.py             # All REST endpoints (~45 KB)
│   │   └── ws.py                 # WebSocket event broadcasting
│   ├── detection/
│   │   ├── rules.py              # Deterministic rule engine (10+ rules)
│   │   ├── ueba.py               # IsolationForest + per-user profiles
│   │   ├── score.py              # Composite risk scoring (0–100)
│   │   ├── evaluate.py           # Live session evaluation pipeline
│   │   ├── live.py               # Real-time detection orchestrator
│   │   └── response.py           # Adaptive response policy engine
│   ├── models/
│   │   ├── db.py                 # SQLAlchemy engine + session factory
│   │   └── entities.py           # ORM models (User, Session, Event, etc.)
│   ├── security/
│   │   ├── auth.py               # JWT authentication + password hashing
│   │   ├── pqc.py                # Post-quantum crypto abstraction layer
│   │   ├── vault.py              # PQC-encrypted credential vault
│   │   ├── audit.py              # Hash-chained + ML-DSA signed audit log
│   │   └── keys.py               # Key management (vault + audit keypairs)
│   └── simulator/
│       ├── seed.py               # Database seeder (14-day baseline)
│       ├── normal.py             # Normal workday activity generator
│       └── attack.py             # Attack scenario simulator
├── frontend/                     # React SOC dashboard
│   ├── src/
│   │   ├── App.jsx               # Root component with routing
│   │   ├── main.jsx              # React entrypoint
│   │   ├── api.js                # Backend API client
│   │   ├── ui.js                 # Shared UI components
│   │   ├── index.css             # Tailwind + custom styles
│   │   ├── components/           # Reusable React components
│   │   └── pages/                # Page-level views
│   ├── index.html                # HTML shell
│   ├── vite.config.js            # Vite build config
│   └── package.json              # Frontend dependencies
├── tests/                        # pytest test suite
│   ├── test_health.py            # Health check
│   ├── test_bank.py              # Banking operations
│   ├── test_detection.py         # Detection engine
│   ├── test_phase3.py            # Attack scenarios & response
│   ├── test_pqc.py               # Post-quantum crypto
│   ├── test_pam_plus.py          # PAM, vault, JIT workflows
│   ├── test_portal.py            # Employee portal flows
│   ├── test_scenarios.py         # End-to-end scenarios
│   └── test_simulator.py         # Simulator validation
├── run.ps1                       # One-command start (Windows PowerShell)
├── run.sh                        # One-command start (Linux/macOS/Git Bash)
├── Dockerfile                    # Container build
├── docker-compose.yml            # Docker Compose orchestration
├── requirements.txt              # Python dependencies
└── .env.example                  # Environment variable template
```

---

## 🚀 Getting Started

### Prerequisites
- **Python 3.12+**
- **Node.js 18+** (for frontend build)
- **Git**

### One-Command Start

**Windows (PowerShell):**
```powershell
.\run.ps1
```

**Linux / macOS / Git Bash:**
```bash
./run.sh
```

This single command handles everything:
1. ✅ Creates a Python virtual environment
2. ✅ Installs all backend dependencies
3. ✅ Seeds the database with 14 days of simulated baseline activity
4. ✅ Builds the React frontend
5. ✅ Starts the Uvicorn server on `http://localhost:8000`

### Docker Alternative
```bash
docker compose up --build
```

### Clean Demo Reset
```powershell
.\run.ps1 -Reset          # Windows
./run.sh --reset           # Linux/macOS
```
Wipes and re-seeds the database for a fresh demo state.

---

## 🎮 Demo Walkthrough

> **Open two browser windows side by side — SOC Console and Employee Portal — to see detection and response happen in real time.**

### Login Credentials

| Username | Password | Role | Lands In |
|:---:|:---:|---|---|
| `soc_admin` | `prahari123` | SOC Analyst | **SOC Console** — monitors all privileged activity live |
| `rmehta` | `prahari123` | Database Administrator | **Employee Portal** — performs legitimate privileged tasks |
| `ext_dsouza` | `prahari123` | External Contractor (Dormant) | **Employee Portal** — the attacker scenario |

### Scenario 1: Normal Day (Low Risk ✅)

1. Log in as **`rmehta`** (DBA) in the Employee Portal
2. Perform normal banking operations — query accounts, process transfers
3. Watch the SOC Console: risk score stays **green (0–39)**, status is `ALLOW`
4. All actions are recorded in the session transcript

### Scenario 2: Insider Attack (High Risk 🚫)

1. Log in as **`ext_dsouza`** (dormant vendor) in the Employee Portal
2. **Immediately triggers:** `DORMANT_REACTIVATION` rule (+30 pts)
3. Attempt privileged operations — mass data export, privilege escalation
4. Watch the SOC Console: risk score **rockets to CRITICAL**, session gets `BLOCKED`
5. The credential vault **denies checkout** to the blocked session
6. Every action is hash-chained and signed in the tamper-evident audit log

### Scenario 3: Step-Up MFA Challenge (Medium Risk 🔑)

1. When a session triggers `STEP_UP_MFA`, the employee sees an MFA prompt
2. Enter the demo MFA code: **`246810`**
3. The SOC Console shows the challenge and its outcome in real time

### Scenario 4: JIT Privilege Elevation

1. As `rmehta`, request a JIT elevation for a resource (e.g., `core-banking-db`)
2. Switch to the SOC Console as `soc_admin`
3. See the pending JIT request → Approve or Deny it
4. If approved, `rmehta`'s privilege escalation on that resource is **sanctioned** — the rule engine recognizes the active JIT grant and does **not** fire `PRIVILEGE_ESCALATION`

---

## 🧠 Detection Engine Deep Dive

### Rule Engine (Deterministic)

| Rule | Insider Type | Weight | Trigger |
|---|:---:|:---:|---|
| `DORMANT_REACTIVATION` | 🔴 Malicious | 30 | Dormant/vendor account logs in |
| `PRIVILEGE_ESCALATION` | 🔴 Malicious | 25 | Unauthorized privilege change (no JIT grant) |
| `AFTER_HOURS_ACCESS` | 🔴 Malicious | 20 | Activity between 00:00–06:00 |
| `MASS_EXPORT` | 🔴 Malicious | 30 | ≥1,000 records exported in one session |
| `NO_BUSINESS_RELATIONSHIP` | 🔴 Malicious | 15 | Accessing resources outside assigned role |
| `NEW_GEO` | 🟠 Compromised | 16 | Login from unrecognized location |
| `NEW_DEVICE` | 🟠 Compromised | 12 | Unrecognized device + foreign location |
| `ATYPICAL_HOUR` | 🟠 Compromised | 8 | Login at unusual time for this user |
| `RAPID_FIRE` | 🟠 Compromised | 8 | 5+ actions in ≤180s (automated/bot) |
| `EXPIRED_ACCESS_IN_USE` | 🟡 Negligent | 30 | Using an expired access grant |
| `UNMANAGED_DEVICE` | 🟡 Negligent | 30 | Sensitive data on non-corporate device |

### UEBA Model (AI/ML)

```
Feature Vector (per session):
┌─────────────┬────────────────┬─────────────────┬──────────────────┐
│ Login Hour  │  Event Count   │ Records Touched │ Distinct Resources│
├─────────────┼────────────────┼─────────────────┼──────────────────┤
│Config Changes│  Off-Network  │   New Device    │                  │
└─────────────┴────────────────┴─────────────────┴──────────────────┘
          │
          ▼
   IsolationForest (100 estimators, trained on 14-day baseline)
          │
          ▼
   Anomaly Score (0–100) + Per-User Behavioural Profile
```

- **IsolationForest** — unsupervised ML trained on closed historical sessions (cumulative prefixes for partial-session scoring)
- **Per-User Baseline** — learned hours, devices, geo-locations, data volume patterns for each privileged user
- **Peer Comparison** — compares the current session's data volume against same-role peer averages
- **Explainability** — anomaly factors expressed in human language: *"device LAPTOP-XYZ never used by this account"*

### Risk Score Formula

```
Risk Score = min(Rule Points + UEBA Points + Peer Bonus, 100)

Where:
  Rule Points = min(Σ rule weights, 80)       # capped at 80
  UEBA Points = anomaly_score × 0.25          # max 25 pts
  Peer Bonus  = 10 if peer_deviation ≥ 5x     # extra for outliers
```

---

## 🔐 Post-Quantum Cryptography (PQC)

Prahari is **quantum-ready**. All cryptographic operations use NIST-standardized post-quantum algorithms, protecting against "harvest now, decrypt later" attacks:

| Component | Algorithm | Standard | Purpose |
|---|---|---|---|
| **Credential Vault** | ML-KEM-768 + AES-256-GCM | FIPS 203 | Encrypt privileged credentials (DB root passwords, API keys, SWIFT passphrases) |
| **Audit Log** | ML-DSA-65 + SHA-256 chain | FIPS 204 | Sign each audit entry; hash-chain ensures tamper evidence |

### How the Vault Works

```
Store:  Secret → ML-KEM-768 Encapsulate(vault_pub) → shared_key
        → AES-256-GCM Encrypt(shared_key, secret) → ciphertext + kem_ct

Retrieve: kem_ct → ML-KEM-768 Decapsulate(vault_sec) → shared_key
          → AES-256-GCM Decrypt(shared_key, ciphertext) → Secret
```

### Provider Abstraction
The PQC layer auto-selects the best available provider:
1. **`liboqs-python`** (native C) — fastest, used if installed
2. **`kyber-py` + `dilithium-py`** (pure Python) — zero compiler dependency, works everywhere

---

## 📡 API Reference

| Method | Endpoint | Description |
|:---:|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/api/login` | Authenticate and receive JWT |
| `GET` | `/api/me` | Current user profile |
| `GET` | `/api/sessions` | All sessions (SOC view) |
| `GET` | `/api/sessions/{id}` | Session detail with events & risk |
| `POST` | `/api/portal/action` | Employee performs a privileged action |
| `GET` | `/api/alerts` | Alert feed (filterable by severity) |
| `POST` | `/api/mfa/verify` | Verify step-up MFA challenge |
| `GET` | `/api/vault/credentials` | List vault items + checkout history |
| `POST` | `/api/vault/checkout` | Risk-gated credential checkout |
| `POST` | `/api/jit/request` | Request JIT privilege elevation |
| `POST` | `/api/jit/decide` | Approve/deny a JIT grant (SOC) |
| `GET` | `/api/audit/log` | View signed audit entries |
| `GET` | `/api/audit/verify` | Verify audit chain integrity |
| `GET` | `/api/pam/access-review` | PAM access review dashboard |
| `GET` | `/api/ueba/model` | UEBA model card & stats |
| `WS` | `/ws/events` | Real-time event stream (WebSocket) |

---

## 🧪 Testing

Run the full test suite:

```bash
# Activate the virtual environment first
.\.venv\Scripts\activate        # Windows
source .venv/bin/activate       # Linux/macOS

# Run all tests
pytest tests/ -v
```

### Test Coverage

| Test File | Covers |
|---|---|
| `test_health.py` | Server liveness |
| `test_bank.py` | Banking operations, accounts, transfers |
| `test_detection.py` | Rule engine, UEBA scoring, risk assessment |
| `test_phase3.py` | Attack scenarios, adaptive response, WebSocket |
| `test_pqc.py` | Post-quantum encryption/decryption, key exchange |
| `test_pam_plus.py` | PAM workflows, vault checkout, JIT grants |
| `test_portal.py` | Employee portal end-to-end flows |
| `test_scenarios.py` | Multi-step insider attack simulations |
| `test_simulator.py` | Data seeder & baseline generator |


