# Prahari
### AI-Powered Privileged-Access & Insider Threat Detection Platform

Privileged-access **insider-threat detection platform** for banks — FinSpark'26
(Bank of Maharashtra), Problem Statement 1.

Watches privileged users, scores their behaviour in real time (rules + UEBA),
responds adaptively (step-up MFA / block), and protects its credentials and
audit log with post-quantum cryptography (ML-KEM-768 / ML-DSA-65).

## Quick start

```powershell
.\run.ps1            # Windows PowerShell  (or ./run.sh in Git Bash / Linux)
# then open http://127.0.0.1:8000  — the login screen
```

One command: venv + deps + seeded DB + web app + API. `-Reset` (or `--reset`)
wipes the DB for a clean demo state. Docker alternative: `docker compose up --build`

### Two sides, one app (all password `prahari123`)

| Login | Lands in | Role |
|---|---|---|
| `soc_admin` | **SOC Console** | security analyst watching every privileged session live |
| `rmehta` | **Employee Portal** | a normal DBA performing privileged actions |
| `ext_dsouza` | **Employee Portal** | the dormant vendor — the attacker |

Staff act in the portal; every action is scored and enforced live (allow /
step-up MFA / maker-checker / block); the SOC console sees it all in real time.
Step-up MFA demo code: `246810`. Run the two windows side by side.

## Layout

- `app/` — FastAPI backend (api, models, detection, security, simulator)
- `frontend/` — React SOC dashboard (Phase 5)
- `tests/` — pytest suite

## Status

- [x] Phase 0 — scaffold, `/health`
- [x] Phase 1 — data model + normal-day simulator
- [x] Phase 2 — rules + UEBA + risk scoring
- [x] Phase 3 — attack scenario + adaptive response + WebSocket
- [x] Phase 4 — PQC vault + signed audit chain (liboqs: ML-KEM-768 + ML-DSA-65)
- [x] Phase 5 — SOC dashboard (React + Vite + Tailwind + Recharts)
- [x] Phase 6 — demo hardening (one-command offline start)

