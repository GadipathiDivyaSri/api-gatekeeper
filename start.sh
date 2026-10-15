#!/usr/bin/env bash
set -e

# Create data directory if needed (ephemeral on Render)
mkdir -p "${DATA_DIR:-data}"

# Seed the demo database
python -m backend.seed

# Start the backend on localhost only (not exposed to the internet)
uvicorn backend.app:app --host 127.0.0.1 --port 9000 &

# Wait for backend to become ready
sleep 2

# Start the gateway on all interfaces (Render provides $PORT)
exec uvicorn gateway.main:app --host 0.0.0.0 --port "${PORT:-8000}"
