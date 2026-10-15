"""
API Gatekeeper Main Application (Module M2).
FastAPI application factory, lifespan client management, health check endpoint,
and transparent reverse proxy catch-all route.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from gateway.config import GatewayConfig, get_config
from gateway.proxy import proxy_forward


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
    """Manage shared HTTP client lifecycle for upstream proxying."""
    client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)
    app.state.http_client = client
    yield
    await client.aclose()


def create_app(config: GatewayConfig | None = None) -> FastAPI:
    """Application factory for API Gatekeeper."""
    app_config = config or get_config()

    app = FastAPI(
        title="API Gatekeeper",
        version="1.0.0",
        description="Drop-in reverse-proxy security gateway for REST APIs.",
        lifespan=lifespan,
    )
    app.state.config = app_config

    # -------------------------------------------------------------------------
    # Control Plane Endpoints
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
    # Catch-all Reverse Proxy Route (Registered LAST)
    # -------------------------------------------------------------------------

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def catch_all_proxy(path: str, request: Request) -> Response:
        """Transparent reverse proxy route forwarding requests to upstream backend."""
        incident_id = generate_incident_id()
        client_ip = resolve_client_ip(request, app.state.config.client_ip_source)

        # Enforce max body size
        body = await request.body()
        if len(body) > app.state.config.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "Payload too large",
                    "incident_id": incident_id,
                },
            )

        client: httpx.AsyncClient = app.state.http_client
        query_string = request.url.query
        headers = dict(request.headers.items())

        return await proxy_forward(
            client=client,
            upstream_url=app.state.config.upstream_url,
            method=request.method,
            path=path,
            query_string=query_string,
            headers=headers,
            body=body,
            client_ip=client_ip,
            incident_id=incident_id,
        )

    return app


app = create_app()
