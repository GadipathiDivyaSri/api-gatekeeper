#!/usr/bin/env bash
set -e

echo "============================================================"
echo "   API Gatekeeper - Cloud / Render Production Startup       "
echo "============================================================"

# 1. Ephemeral disk initialization
export DATA_DIR="${DATA_DIR:-data}"
mkdir -p "$DATA_DIR"
echo "[+] Initialized DATA_DIR at: $DATA_DIR"

# 2. Seed DemoShop database on boot
echo "[*] Seeding DemoShop database..."
python -m backend.seed

# 3. Start DemoShop backend (bound strictly to 127.0.0.1:9000, internal only)
echo "[*] Starting internal backend on 127.0.0.1:9000..."
uvicorn backend.app:app --host 127.0.0.1 --port 9000 &

# 4. Wait for internal backend readiness
echo "[*] Waiting for backend readiness..."
for i in $(seq 1 20); do
    if python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/api/health', timeout=1)" >/dev/null 2>&1; then
        echo "[+] DemoShop backend is healthy."
        break
    fi
    sleep 0.5
done

# 5. Start API Gatekeeper on $PORT (listens publicly on 0.0.0.0)
echo "[*] Starting API Gatekeeper on 0.0.0.0:${PORT:-8000}..."
exec uvicorn gateway.main:app --host 0.0.0.0 --port "${PORT:-8000}"
