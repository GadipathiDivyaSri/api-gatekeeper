# API Gatekeeper

A drop-in reverse-proxy security gateway for REST APIs.  
Inspects every request, blocks injection/bot/abuse traffic, logs security events, and proves its own effectiveness with a live scorecard.

## Quick Start (Windows)

```cmd
:: 1. Clone the repository
git clone https://github.com/GadipathiDivyaSri/api-gatekeeper.git
cd api-gatekeeper

:: 2. Create a virtual environment
python -m venv .venv

:: 3. Activate the virtual environment
.venv\Scripts\activate

:: 4. Install dependencies
pip install -r requirements.txt

:: 5. Launch the demo (starts backend + gateway)
run_demo.bat
```

Open **http://127.0.0.1:8000/_gk/** in your browser to view the live dashboard.

## Architecture

```
Client → [API Gatekeeper :8000] → [DemoShop Backend :9000]
              │
              ├─ Normaliser (multi-decode)
              ├─ Bot detection
              ├─ Contract Guard (OpenAPI)
              ├─ Signature engine (rules.yaml)
              ├─ Rate limiter + bans
              ├─ Response Shield
              └─ Live Dashboard (/_gk/)
```

## Threat Coverage

| Threat | OWASP | CWE |
|--------|-------|-----|
| SQL injection | A03:2021 | CWE-89 |
| NoSQL injection | A03:2021 | CWE-943 |
| Cross-site scripting | A03:2021 | CWE-79 |
| OS command injection | A03:2021 | CWE-78 |
| Path traversal | A01:2021 | CWE-22 |
| SSRF | A10:2021 | CWE-918 |
| Log4Shell / JNDI | A03:2021 | CWE-917 |
| Mass assignment | API3:2023 | CWE-915 |
| Undocumented endpoints | API9:2023 | CWE-1059 |
| Credential stuffing | API2:2023 | CWE-307 |
| Floods / scraping | API4:2023 | CWE-770 |
| Scanner tools | A05:2021 | CWE-200 |
| Error / stack-trace leakage | A05:2021 | CWE-209 |

## Stack

- **Gateway:** Python 3.12, FastAPI, uvicorn[standard], httpx
- **Rules:** YAML + precompiled regex, hot-reloadable
- **Storage:** SQLite (WAL) + JSONL
- **Dashboard:** HTML + vanilla JS + Chart.js 4.4.1 (vendored)
- **Backend:** FastAPI "DemoShop" with parameterised queries
- **Deploy:** Render free tier (or any platform)

## Project Structure

```
api-gatekeeper/
├─ gateway/          Pipeline, proxy, rules engine, dashboard
├─ config/           gateway.yaml, rules.yaml
├─ backend/          DemoShop sample API
├─ tools/            Attack simulator, demo traffic, benchmarks
├─ tests/            pytest suite + attack/benign corpus
├─ docs/             Master context, demo script
├─ data/             Runtime data (gitignored)
├─ requirements.txt
├─ run_demo.bat      Windows demo launcher
├─ start.sh          Linux/Render launcher
└─ README.md
```

## License

Built for InnoHacks 2.0 Hackathon — Cybersecurity Track.
