"""
Response Shield Module (Module M9).
Defensive response transformation layer for proxied API responses:
- Masks upstream server errors (>= 500) preventing stack trace and internal leakages.
- Strips information-disclosing headers (Server, X-Powered-By).
- Injects standard defensive security headers (X-Content-Type-Options, X-Frame-Options,
  Referrer-Policy, Cache-Control, Content-Security-Policy).
- Leaves dashboard and control plane routes (/_gk/*) unaffected.
"""

from __future__ import annotations

from typing import Mapping
from fastapi.responses import JSONResponse

# Headers that reveal backend software or framework version information
STRIP_HEADERS: set[str] = {
    "server",
    "x-powered-by",
}

# Defensive security headers applied to all proxied API responses
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'",
}

# Hop-by-hop & streaming response headers dropped during proxying
DROP_RESPONSE_HEADERS: set[str] = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
}


def should_mask_response(status_code: int) -> bool:
    """Return True if HTTP status code represents an internal server error (>= 500)."""
    return status_code >= 500


def apply_shield_headers(
    raw_headers: Mapping[str, str] | dict[str, str] | None = None,
) -> dict[str, str]:
    """
    Sanitize response headers:
    1. Strip information-leaking headers (Server, X-Powered-By).
    2. Strip hop-by-hop / transfer / encoding headers.
    3. Inject defensive HTTP security headers.
    """
    clean_headers: dict[str, str] = {}
    if raw_headers:
        for key, value in raw_headers.items():
            key_lower = key.lower()
            if key_lower not in STRIP_HEADERS and key_lower not in DROP_RESPONSE_HEADERS:
                clean_headers[key] = value

    for sec_key, sec_val in SECURITY_HEADERS.items():
        clean_headers[sec_key] = sec_val

    return clean_headers


def create_masked_error_response(
    status_code: int,
    incident_id: str,
    base_headers: Mapping[str, str] | dict[str, str] | None = None,
) -> JSONResponse:
    """
    Generate a sanitized generic JSON response masking backend 500+ stack traces and errors.
    """
    headers = apply_shield_headers(base_headers or {})
    return JSONResponse(
        status_code=status_code,
        content={
            "error": "Internal error",
            "incident_id": incident_id,
        },
        headers=headers,
    )
