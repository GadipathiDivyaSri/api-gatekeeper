"""
API Gatekeeper Main Application (Modules M2, M3, M4 & M5).
FastAPI application factory, lifespan client & event worker management,
control plane admin endpoints, WebSocket live broadcast, and transparent proxy.
"""

from __future__ import annotations

import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from gateway.admin import admin_router
from gateway.config import GatewayConfig, get_config
from gateway.events import EventStore, get_event_store
from gateway.models import Event, RequestContext
from gateway.pipeline import inspect
from gateway.proxy import proxy_forward
from gateway.ratelimit import BanManager, RateLimiter, get_ban_manager, get_rate_limiter
from gateway.rules import RuleManager, get_rule_manager
from gateway.ws import WebSocketManager, get_ws_manager


def generate_incident_id() -> str:
    """Generate incident ID formatted as AG-YYYYMMDD-HHMMSS-xxxx."""
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = secrets.token_hex(2)
    return f"AG-{now_str}-{suffix}"


def resolve_client_ip(request: Request, ip_source: str) -> str:
    """Resolve client IP according to configured client_ip_source strategy."""
    socket_ip = request.client.host if request.client else "127.0.0.1"
    xff = request.headers.get("x-forwarded-for")

    if not xff:
        return socket_ip

    ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
    if not ips:
        return socket_ip

    if ip_source == "xff_first":
        return ips[0]
    elif ip_source == "xff_last":
        return ips[-1]
    return socket_ip


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage HTTP client lifecycle, rules precompilation, and event store batch worker."""
    client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    app.state.http_client = client
    app.state.rule_manager = get_rule_manager()
    app.state.rate_limiter = get_rate_limiter(app.state.config)
    app.state.ban_manager = get_ban_manager(app.state.config)

    # Initialize and start background event batch writer
    app.state.ws_manager = get_ws_manager()
    app.state.event_store = get_event_store(app.state.config.data_dir)
    app.state.event_store.start_worker()

    yield

    # Graceful shutdown
    await app.state.event_store.stop_worker()
    await client.aclose()


def create_app(
    config: GatewayConfig | None = None,
    rule_manager: RuleManager | None = None,
    rate_limiter: RateLimiter | None = None,
    ban_manager: BanManager | None = None,
    event_store: EventStore | None = None,
    ws_manager: WebSocketManager | None = None,
) -> FastAPI:
    """Application factory for API Gatekeeper."""
    app_config = config or get_config()
    active_rules = rule_manager or get_rule_manager()
    active_rl = rate_limiter or get_rate_limiter(app_config)
    active_bans = ban_manager or get_ban_manager(app_config)
    active_ws = ws_manager or get_ws_manager()
    active_events = event_store or get_event_store(app_config.data_dir)

    app = FastAPI(
        title="API Gatekeeper",
        version="1.0.0",
        description="Drop-in reverse-proxy security gateway for REST APIs.",
        lifespan=lifespan,
    )
    app.state.config = app_config
    app.state.rule_manager = active_rules
    app.state.rate_limiter = active_rl
    app.state.ban_manager = active_bans
    app.state.ws_manager = active_ws
    app.state.event_store = active_events
    if not hasattr(app.state, "http_client"):
        app.state.http_client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)

    # -------------------------------------------------------------------------
    # Mount Control Plane Admin Router (/_gk/api/*)
    # -------------------------------------------------------------------------
    app.include_router(admin_router)

    # -------------------------------------------------------------------------
    # Control Plane Health Check
    # -------------------------------------------------------------------------

    @app.get("/_gk/health", tags=["Control Plane"], summary="Gateway and upstream health check")
    async def health_check() -> JSONResponse:
        """Check gateway status and reachability of configured upstream service."""
        client: httpx.AsyncClient = app.state.http_client
        upstream_url = app.state.config.upstream_url.rstrip("/")
        reachable = False

        try:
            resp = await client.get(f"{upstream_url}/api/health", timeout=2.0)
            reachable = resp.status_code < 500
        except Exception:
            try:
                resp = await client.get(upstream_url, timeout=2.0)
                reachable = resp.status_code < 500
            except Exception:
                reachable = False

        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "upstream_reachable": reachable,
                "mode": app.state.config.mode,
            },
        )

    # -------------------------------------------------------------------------
    # Live Event Stream WebSocket Endpoint (/_gk/ws)
    # -------------------------------------------------------------------------

    @app.websocket("/_gk/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """Stream real-time security events to connected dashboard clients."""
        expected_token = app.state.config.admin_token
        header_token = websocket.headers.get("x-admin-token")
        query_token = websocket.query_params.get("token")
        provided_token = header_token or query_token

        if expected_token and provided_token != expected_token:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        ws_mgr: WebSocketManager = app.state.ws_manager
        await ws_mgr.connect(websocket)

        try:
            while True:
                msg = await websocket.receive_text()
                if msg == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            ws_mgr.disconnect(websocket)
        except Exception:
            ws_mgr.disconnect(websocket)

    # -------------------------------------------------------------------------
    # Dashboard Static Assets & UI Page
    # -------------------------------------------------------------------------

    static_path = Path(__file__).parent / "static"
    if static_path.is_dir():
        app.mount("/_gk/static", StaticFiles(directory=str(static_path)), name="static")

    @app.get("/_gk", include_in_schema=False)
    @app.get("/_gk/", include_in_schema=False)
    async def serve_dashboard() -> Response:
        """Serve the live security defense dashboard."""
        index_file = Path(__file__).parent / "static" / "index.html"
        if index_file.is_file():
            return FileResponse(str(index_file))
        return JSONResponse({"error": "Dashboard template not found"}, status_code=404)

    # -------------------------------------------------------------------------
    # Catch-all Reverse Proxy Route (Registered LAST)
    # -------------------------------------------------------------------------

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def catch_all_proxy(path: str, request: Request) -> Response:
        """Inspect and transparently proxy requests to upstream backend."""
        start_time = time.perf_counter()
        incident_id = generate_incident_id()
        client_ip = resolve_client_ip(request, app.state.config.client_ip_source)
        formatted_path = path if path.startswith("/") else f"/{path}"

        # Enforce max body size
        body = await request.body()
        if len(body) > app.state.config.max_body_bytes:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            event = Event(
                incident_id=incident_id,
                ts=time.time(),
                client_ip=client_ip,
                method=request.method,
                path=formatted_path,
                query=request.url.query[:1024],
                user_agent=request.headers.get("user-agent", "")[:256],
                body_excerpt="[Oversized payload]",
                decoded_excerpt="",
                action="blocked",
                score=5,
                primary_category="protocol",
                severity="medium",
                findings=[{"layer": "gateway", "rule_id": "MAX_BODY", "name": "Payload too large"}],
                status_code=413,
                latency_ms=round(latency_ms, 2),
                upstream_ms=0.0,
                reached_backend=False,
            )
            app.state.event_store.emit(event)
            return JSONResponse(
                status_code=413,
                content={"error": "Payload too large", "incident_id": incident_id},
            )

        # Extract parameters and decode body text for inspection
        query_params: dict[str, list[str]] = {}
        for k, v in request.query_params.multi_items():
            query_params.setdefault(k, []).append(v)

        body_text = ""
        if body:
            try:
                body_text = body.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""

        headers_dict = dict(request.headers.items())
        content_type = request.headers.get("content-type", "")
        user_agent = request.headers.get("user-agent", "")

        ctx = RequestContext(
            incident_id=incident_id,
            client_ip=client_ip,
            method=request.method,
            path=formatted_path,
            query_string=request.url.query,
            query_params=query_params,
            headers=headers_dict,
            user_agent=user_agent,
            body_bytes=body,
            body_text=body_text,
            content_type=content_type,
        )

        # Pure inspection pipeline (ban check -> rate limit -> signatures -> scoring)
        decision = inspect(
            ctx,
            config=app.state.config,
            rules_manager=app.state.rule_manager,
            rate_limiter=app.state.rate_limiter,
            ban_manager=app.state.ban_manager,
        )

        # Helper to determine primary category and severity
        primary_category = "none"
        severity = "none"
        if decision.findings:
            primary_category = decision.findings[0].category
            sev_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            sorted_by_sev = sorted(
                decision.findings,
                key=lambda f: sev_levels.get(getattr(f, "severity", "medium").lower(), 0),
                reverse=True,
            )
            severity = getattr(sorted_by_sev[0], "severity", "medium")
        elif decision.action == "rate_limited":
            primary_category = "rate_limit"
            severity = "medium"
        elif decision.action == "banned":
            primary_category = "ban"
            severity = "high"

        # Handle early termination (banned, rate_limited, blocked)
        if decision.action in ("banned", "rate_limited", "blocked"):
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            event = Event(
                incident_id=incident_id,
                ts=time.time(),
                client_ip=client_ip,
                method=request.method,
                path=formatted_path,
                query=request.url.query[:1024],
                user_agent=user_agent[:256],
                body_excerpt=body_text[:2048],
                decoded_excerpt="",
                action=decision.action,
                score=decision.score,
                primary_category=primary_category,
                severity=severity,
                findings=[f.to_dict() for f in decision.findings],
                status_code=decision.status_code,
                latency_ms=round(latency_ms, 2),
                upstream_ms=0.0,
                reached_backend=False,
            )
            app.state.event_store.emit(event)

            headers: dict[str, str] = {}
            if decision.retry_after:
                headers["retry-after"] = str(decision.retry_after)

            if decision.action == "banned":
                return JSONResponse(
                    status_code=403,
                    content={"error": "IP temporarily banned", "incident_id": incident_id},
                    headers=headers,
                )
            if decision.action == "rate_limited":
                return JSONResponse(
                    status_code=429,
                    content={"error": "Too Many Requests", "incident_id": incident_id},
                    headers=headers,
                )
            return JSONResponse(
                status_code=403,
                content={"error": "Request blocked", "incident_id": incident_id},
            )

        # Forward allowed or flagged requests to upstream
        upstream_start = time.perf_counter()
        client: httpx.AsyncClient = app.state.http_client

        proxy_response = await proxy_forward(
            client=client,
            upstream_url=app.state.config.upstream_url,
            method=request.method,
            path=path,
            query_string=request.url.query,
            headers=headers_dict,
            body=body,
            client_ip=client_ip,
            incident_id=incident_id,
        )

        upstream_ms = (time.perf_counter() - upstream_start) * 1000.0
        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Emit audit event for proxied request
        event = Event(
            incident_id=incident_id,
            ts=time.time(),
            client_ip=client_ip,
            method=request.method,
            path=formatted_path,
            query=request.url.query[:1024],
            user_agent=user_agent[:256],
            body_excerpt=body_text[:2048],
            decoded_excerpt="",
            action=decision.action,  # "allowed" or "flagged"
            score=decision.score,
            primary_category=primary_category,
            severity=severity,
            findings=[f.to_dict() for f in decision.findings],
            status_code=proxy_response.status_code,
            latency_ms=round(total_latency_ms, 2),
            upstream_ms=round(upstream_ms, 2),
            reached_backend=proxy_response.status_code != 502,
        )
        app.state.event_store.emit(event)

        return proxy_response

    return app


app = create_app()
