#!/usr/bin/env bash
# Prahari one-command demo start (offline once prepped).
#   ./run.sh           start everything (seeds DB on first run)
#   ./run.sh --reset   wipe + reseed the DB first (clean demo state)
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[prahari] creating venv..."
  python -m venv .venv
fi
if [ -f .venv/Scripts/activate ]; then
  source .venv/Scripts/activate   # Windows (Git Bash)
else
  source .venv/bin/activate        # POSIX
fi

# Install deps only if FastAPI is missing (keeps offline restarts instant).
python -c "import fastapi" 2>/dev/null || pip install -q -r requirements.txt

if [ "$1" = "--reset" ] || [ ! -f prahari.db ]; then
  echo "[prahari] seeding 14 days of baseline history..."
  python -m app.simulator.seed --fresh --days 14
fi

# Build the dashboard only if dist/ is absent (repo ships a prebuilt dist).
if [ ! -d frontend/dist ]; then
  echo "[prahari] building frontend..."
  (cd frontend && npm install --no-fund --no-audit && npm run build)
fi

# Bind to 0.0.0.0 so a second computer on the same Wi-Fi/LAN can connect.
LAN=$(python -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);\
s.connect(('8.8.8.8',80));print(s.getsockname()[0]);s.close()" 2>/dev/null || echo "")
echo ""
echo "[prahari] ===================================================="
echo "[prahari]  This computer  : http://localhost:8000"
[ -n "$LAN" ] && echo "[prahari]  Other computers: http://$LAN:8000   (same Wi-Fi/LAN)"
echo "[prahari]  (if the 2nd computer can't connect, allow port 8000 in the firewall)"
echo "[prahari] ===================================================="
echo ""
uvicorn app.main:app --host 0.0.0.0 --port 8000
