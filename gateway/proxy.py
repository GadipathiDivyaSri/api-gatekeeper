"""
Gateway Transparent Proxy Module (Module M2).
Handles upstream forwarding, hop-by-hop header stripping, request ID injection,
and streaming responses with error shielding.
"""

from __future__ import annotations

from typing import AsyncGenerator

import httpx
from fastapi import Response
from fastapi.responses import JSONResponse, StreamingResponse

from gateway.shield import (
    apply_shield_headers,
    create_masked_error_response,
    should_mask_response,
)

# Hop-by-hop headers that must not be forwarded from client to upstream
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def build_forward_headers(
    headers: dict[str, str],
    client_ip: str,
    incident_id: str,
) -> dict[str, str]:
    """Filter hop-by-hop headers and inject proxy tracing headers."""
    clean_headers: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() not in HOP_BY_HOP_HEADERS:
            clean_headers[key] = value

    # Append or set X-Forwarded-For
    existing_xff = clean_headers.get("x-forwarded-for") or clean_headers.get("X-Forwarded-For")
    if existing_xff:
        clean_headers["x-forwarded-for"] = f"{existing_xff}, {client_ip}"
    else:
        clean_headers["x-forwarded-for"] = client_ip

    # Set X-Request-ID to current incident_id
    clean_headers["x-request-id"] = incident_id
    return clean_headers


async def proxy_forward(
    client: httpx.AsyncClient,
    upstream_url: str,
    method: str,
    path: str,
    query_string: str,
    headers: dict[str, str],
    body: bytes,
    client_ip: str,
    incident_id: str,
) -> tuple[Response, bool]:
    """
    Forward incoming request to upstream service and stream shielded response back.
    Returns (response, error_masked).
    """
    target_path = "/" + path.lstrip("/")
    target_url = upstream_url.rstrip("/") + target_path
    if query_string:
        target_url = f"{target_url}?{query_string}"

    forward_headers = build_forward_headers(headers, client_ip, incident_id)

    req = client.build_request(
        method=method,
        url=target_url,
        content=body if body else None,
        headers=forward_headers,
    )

    # Strip any hop-by-hop headers injected by httpx defaults
    for hop_header in HOP_BY_HOP_HEADERS:
        if hop_header != "host" and hop_header in req.headers:
            del req.headers[hop_header]

    try:
        upstream_resp = await client.send(req, stream=True)
    except (
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.TimeoutException,
        httpx.NetworkError,
    ):
        shielded_502_headers = apply_shield_headers({})
        return (
            JSONResponse(
                status_code=502,
                content={
                    "error": "Bad Gateway: Upstream service unavailable",
                    "incident_id": incident_id,
                },
                headers=shielded_502_headers,
            ),
            False,
        )

    # If upstream returned an internal server error (>= 500), mask it
    if should_mask_response(upstream_resp.status_code):
        await upstream_resp.aclose()
        masked_resp = create_masked_error_response(
            status_code=upstream_resp.status_code,
            incident_id=incident_id,
            base_headers=dict(upstream_resp.headers),
        )
        return masked_resp, True

    # Clean response headers with defensive security headers
    clean_resp_headers = apply_shield_headers(dict(upstream_resp.headers))

    async def body_stream() -> AsyncGenerator[bytes, None]:
        try:
            async for chunk in upstream_resp.aiter_bytes():
                yield chunk
        finally:
            await upstream_resp.aclose()

    return (
        StreamingResponse(
            content=body_stream(),
            status_code=upstream_resp.status_code,
            headers=clean_resp_headers,
        ),
        False,
    )
