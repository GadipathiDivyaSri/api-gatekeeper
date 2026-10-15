# API Gatekeeper — Master Context for AI Coding Agents

## Mission
API Gatekeeper is a reverse-proxy security gateway for REST APIs, built for the InnoHacks 2.0 hackathon
(problem: "API Gatekeeper"). It inspects every request, blocks malicious traffic, logs security events,
and shows attack analytics on a live dashboard. Differentiators: (1) OpenAPI Contract Guard,
(2) a built-in Security Scorecard measuring detection rate, false-positive rate and latency.
This is a DEFENSIVE product. We build detection, blocking, logging and analytics only.

## Topology
- Sample backend "DemoShop": FastAPI on 127.0.0.1:9000 (backend/app.py). Harmless and written securely
  (parameterised queries, validated input). It is only the thing being protected.
- Gateway: FastAPI on 0.0.0.0:8000 (gateway/main.py). Control plane under /_gk/*. All other paths are proxied.
- Run with ONE uvicorn worker (rate-limit and ban state are in memory).

## Hard constraints
1. Python 3.12. Must run on Windows 10/11 (cmd and PowerShell) and Linux (Render). Use pathlib. Use 127.0.0.1,
   never "localhost". Windows run instructions must not use bash-only syntax.
2. Dependencies ONLY: fastapi, uvicorn[standard], httpx, pyyaml, jsonschema, pytest
   (+ scikit-learn, numpy only in the stretch anomaly module). Add nothing else.
3. Frontend: plain HTML + CSS + vanilla JS + Chart.js 4.4.1 from gateway/static/vendor/chart.umd.js.
   No CDN, no frameworks, no build step.
4. Never execute OS commands, read system files or make outbound requests based on request content, anywhere.
   The backend must be secure; it must not contain deliberately exploitable code.
5. No TODOs, stubs, placeholder data or fake numbers. Every metric shown is computed from real events.
6. Client-facing block responses are generic: {"error": "...", "incident_id": "..."}. Never reveal rule ids,
   patterns or scores to the client. Detail goes only to logs and the dashboard.
7. No SQLite writes in the request path: events go through an asyncio.Queue drained by one background writer.
8. Only modify files listed in the current module's scope.
9. Type hints on all functions; small functions; a module docstring explaining purpose.
10. After implementing, run the module's tests/checks, SHOW the output, then STOP and wait.

## Pipeline order (gateway/pipeline.py)
intake (incident_id, client IP, 1 MB limit -> 413) -> ban check -> rate limit -> normalise -> bot signals ->
contract guard -> signature rules -> [anomaly, stretch] -> score and decide -> proxy -> response shield -> emit event.
`inspect(ctx) -> Decision` is a pure function of request + current state so /_gk/api/test and the
benchmark reuse it in dry-run mode without forwarding.

## Scoring
critical=5, high=4, medium=3, low=2; sum of DISTINCT matched rules; BLOCK_THRESHOLD=5.
mode=block -> 403. mode=monitor -> forward, action "flagged".
Strikes: blocked +1, every 20 rate_limited +1; >=3 strikes in 60 s -> ban 120 s. Values in config/gateway.yaml.

## Client IP resolution (CLIENT_IP_SOURCE)
"socket" (default): request.client.host · "xff_first": first X-Forwarded-For entry (LOCAL DEMO ONLY, lets the
simulator present many client IPs) · "xff_last": last entry (behind exactly one trusted proxy, e.g. Render).

## Normaliser
For each inspection target produce variants: raw; iterative decode up to 3 rounds until stable of
(urllib.parse.unquote_plus -> html.unescape -> unicodedata NFKC -> strip \x00); then collapse SQL inline
comments /**/ to a space and whitespace runs to one space. Base64 only for tokens matching
[A-Za-z0-9+/_-]{12,}={0,2}, decoded, kept only if >=80% printable ASCII.
JSON bodies: flatten recursively; inspect BOTH keys and values. Form bodies: parse_qs.
Targets: path, each query value (+ raw query), body keys/values, header values, user-agent.
Record the decode chain for the dashboard.

## Rules (config/rules.yaml)
Fields: id, name, category, pattern (Python regex, SINGLE-QUOTED in YAML), targets [path|query|body|headers|ua],
score, severity, cwe, owasp, attack, enabled (default true). Compile at load; an invalid regex is logged and
skipped, never crashes. Hot-reload via POST /_gk/api/rules/reload.

## Response Shield
Upstream status >= 500: replace body with {"error":"Internal error","incident_id":...}, log action "error_masked".
Strip Server and X-Powered-By. Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
Referrer-Policy: no-referrer, Cache-Control: no-store, Content-Security-Policy: default-src 'none'
(proxied API responses only, NOT the dashboard).

## Proxy hygiene
One shared httpx.AsyncClient (created in lifespan, closed on shutdown), timeout 10 s, follow_redirects=False.
Strip hop-by-hop headers and host; add X-Forwarded-For and X-Request-ID=incident_id. Drop content-encoding and
content-length from responses. Upstream down -> 502 generic JSON.

## Dashboard WebSocket URL
(location.protocol==='https:'?'wss':'ws') + '://' + location.host + '/_gk/ws'. The catch-all proxy route is registered LAST.

## Env / config
UPSTREAM_URL=http://127.0.0.1:9000 · GATEWAY_MODE=block · ADMIN_TOKEN= (empty = open, local only) ·
DEMO_MODE=true · CLIENT_IP_SOURCE=socket · DATA_DIR=data · OPENAPI_SOURCE=upstream (or a file path)
