# API Gatekeeper — Deployment & Demo Guide (Module M11)

This document provides exact, step-by-step instructions for deploying API Gatekeeper to **Render** (cloud backup) and running the **Windows local demo runner** (primary presentation path).

---

## 1. Architecture Overview

In production or cloud preview mode on Render, API Gatekeeper runs as a **single web service**:
- **Internal DemoShop Backend**: Runs on `127.0.0.1:9000` (internal loopback only, unreachable from the public internet).
- **API Gatekeeper Gateway**: Binds to `0.0.0.0` on the public `$PORT` provided by Render.
- **Ephemeral Storage**: All SQLite data and JSONL logs reside in `DATA_DIR` (`data/`), which is automatically provisioned and seeded by `start.sh` upon boot.
- **Liveness Probe**: Render checks `/_gk/health?shallow=1`, which responds in under 5 ms without hitting upstream services.

---

## 2. Deploying to Render

### Option A: Automated Blueprint Deployment (Recommended)
API Gatekeeper includes a declarative [`render.yaml`](render.yaml) blueprint:

1. Push your repository to GitHub.
2. Log into the [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Select your repository.
5. Render reads `render.yaml` and provisions:
   - Runtime: `Python 3.12`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `bash start.sh`
   - Health Check: `/_gk/health?shallow=1`
   - Auto-generated `ADMIN_TOKEN` secret.
6. Click **Apply**.

---

### Option B: Manual Web Service Setup
If configuring manually via the Render UI:

1. Go to **Render Dashboard** → **New +** → **Web Service**.
2. Connect your repository.
3. Configure settings:
   - **Name**: `api-gatekeeper`
   - **Region**: Closest to your presentation location (e.g., Singapore, Frankfurt, Oregon)
   - **Branch**: `main`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `bash start.sh`
   - **Plan**: Free (or Starter)
4. Under **Advanced**, add **Health Check Path**:
   - `/_gk/health?shallow=1`
5. Add the following **Environment Variables**:

| Variable | Value | Description |
|---|---|---|
| `ADMIN_TOKEN` | `<generate-strong-random-string>` | Secret token guarding `/_gk/api/*` and `/_gk/ws`. |
| `GATEWAY_MODE` | `block` | Default operating mode (`block` or `monitor`). |
| `DEMO_MODE` | `true` | Enables payload tester and benchmark endpoints. |
| `CLIENT_IP_SOURCE` | `xff_first` | *Demo only* — permits simulator to emulate distinct client IPs. |
| `UPSTREAM_URL` | `http://127.0.0.1:9000` | Local loopback address of the backend service. |
| `PYTHON_VERSION` | `3.12` | Ensures modern Python 3.12 runtime. |
| `DATA_DIR` | `data` | Directory for ephemeral SQLite database and event logs. |

6. Click **Create Web Service**.

---

## 3. Accessing the Cloud Dashboard

Once deployed, open your Render service URL in a browser with the admin token:

```
https://<your-service-name>.onrender.com/_gk/?token=<ADMIN_TOKEN>
```

- **WebSocket Auto-detection**: The frontend client automatically connects using `wss://` over HTTPS and transmits the token via query parameter `?token=...`.
- **API Guard**: Any requests to `/_gk/api/*` without the valid token receive `HTTP 401 Unauthorized`.

---

## 4. Security Trade-Off: `CLIENT_IP_SOURCE`

> [!WARNING]
> In production environments behind a trusted reverse proxy (e.g. Cloudflare, AWS ALB), set:
> `CLIENT_IP_SOURCE=xff_last` or `CLIENT_IP_SOURCE=socket`
>
> In the demo setup, `CLIENT_IP_SOURCE=xff_first` is enabled solely so that local or remote test scripts (`attack_sim.py`, `demo_traffic.py`) can send `X-Forwarded-For: <test_ip>` headers to demonstrate per-IP strike tracking, rate limiting, and bans across multiple synthetic attackers. In production, using `xff_first` allows untrusted clients to spoof their source IP.

---

## 5. Free-Tier Behavior & Warm-Up Checklist

Render's free tier spins down web services after 15 minutes of inactivity. When a new request arrives, a cold start takes approximately **50–60 seconds**.

### Pre-Demo 5-Minute Warm-Up Protocol (Judge-Proofing)

Follow this checklist 5 minutes before presenting to judges:

- [ ] **T-5 min — Wake Service**: Send a shallow ping to initiate cold-start if sleeping:
  ```bash
  curl -I "https://<your-service-name>.onrender.com/_gk/health?shallow=1"
  ```
- [ ] **T-4 min — Open Live Dashboard**: Open the dashboard in a pinned browser tab:
  ```
  https://<your-service-name>.onrender.com/_gk/?token=<ADMIN_TOKEN>
  ```
  Verify that the WebSocket status badge indicates `Connected` (green). An open WebSocket connection generates active traffic and prevents Render from idling.
- [ ] **T-3 min — Seed Baseline Traffic**: Generate initial allowed e-commerce traffic:
  ```bash
  python tools/demo_traffic.py --url "https://<your-service-name>.onrender.com" --count 15
  ```
- [ ] **T-2 min — Smoke Test Attack**: Send a single harmless test attack to confirm live detection:
  ```bash
  python tools/attack_sim.py --url "https://<your-service-name>.onrender.com"
  ```
- [ ] **T-1 min — Reset or Confirm Feed**: Check that the live feed, KPI cards, and rolling 60s banner reflect live stats.

---

## 6. Windows Local Demo Runner (Offline / Primary Demo)

For live pitch presentations, running locally on Windows is the most resilient approach (zero reliance on venue Wi-Fi, zero cold starts, zero latency variance).

### Quickstart (Under 60 Seconds):
1. Double-click [`run_demo.bat`](run_demo.bat) (or run from CMD/PowerShell):
   ```cmd
   run_demo.bat
   ```
2. The script automatically:
   - Verifies Python 3.10+ installation.
   - Activates or creates the `.venv` virtual environment.
   - Re-creates and seeds `data/demoshop.db`.
   - Starts DemoShop on `http://127.0.0.1:9000`.
   - Starts API Gatekeeper on `http://127.0.0.1:8000`.
   - Launches your default browser to `http://127.0.0.1:8000/_gk/`.
3. In a separate terminal, run live demos:
   ```cmd
   python tools\attack_sim.py
   python tools\demo_traffic.py
   python tools\walkthrough_m10.py
   ```
