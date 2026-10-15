"""
Gateway Request Normalizer (Module M3).
Multi-decode engine (URL, HTML entities, NFKC Unicode, null byte stripping),
SQL comment/whitespace collapsing, selective Base64 decoding, and recursive body extraction.
"""

from __future__ import annotations

import base64
import html
import json
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from gateway.models import RequestContext


@dataclass
class Variant:
    """A normalized variation of an inspection target with its decoding provenance."""

    text: str
    chain: list[str] = field(default_factory=list)


# Selective Base64 pattern: minimum 12 chars of base64 alphabet, optional 1-2 '=' paddings
BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{12,}={0,2}")
SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
WHITESPACE_RUN_RE = re.compile(r"\s+")


def try_decode_base64(token: str) -> str | None:
    """Decode token if it is valid Base64 and yields >=80% printable ASCII."""
    if len(token) > 4096:
        token = token[:4096]

    # Normalize URL-safe Base64
    normalized = token.replace("-", "+").replace("_", "/")
    missing_padding = len(normalized) % 4
    if missing_padding:
        normalized += "=" * (4 - missing_padding)

    try:
        decoded_bytes = base64.b64decode(normalized, validate=False)
    except Exception:
        return None

    if not decoded_bytes:
        return None

    # Count printable ASCII chars (space to ~ plus tab, LF, CR)
    printable_count = sum(
        1 for b in decoded_bytes if (32 <= b <= 126) or b in (9, 10, 13)
    )
    if (printable_count / len(decoded_bytes)) < 0.8:
        return None

    try:
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def normalize_string(raw: str) -> list[Variant]:
    """
    Produce normalized variants of a string:
    1. Raw string.
    2. Iterative decode (up to 3 rounds of URL unquote, HTML unescape, NFKC, null strip).
    3. Collapse inline SQL comments (/**/) and whitespace runs.
    4. Selective Base64 decode for tokens >=12 chars with >=80% printable content.
    """
    if not raw:
        return [Variant(text="", chain=["raw"])]

    variants: list[Variant] = [Variant(text=raw, chain=["raw"])]
    seen_texts: set[str] = {raw}

    curr = raw
    applied_steps: list[str] = []

    # Iterative decode up to 3 rounds until stable
    for _ in range(3):
        prev = curr

        # 1. URL decode
        if "%" in curr or "+" in curr:
            try:
                unquoted = urllib.parse.unquote_plus(curr)
                if unquoted != curr:
                    curr = unquoted
                    if "url_decode" not in applied_steps:
                        applied_steps.append("url_decode")
            except Exception:
                pass

        # 2. HTML entity unescape
        if "&" in curr:
            try:
                unescaped = html.unescape(curr)
                if unescaped != curr:
                    curr = unescaped
                    if "html_unescape" not in applied_steps:
                        applied_steps.append("html_unescape")
            except Exception:
                pass

        # 3. Unicode NFKC normalization
        try:
            normalized = unicodedata.normalize("NFKC", curr)
            if normalized != curr:
                curr = normalized
                if "nfkc_normalize" not in applied_steps:
                    applied_steps.append("nfkc_normalize")
        except Exception:
            pass

        # 4. Strip null bytes and non-characters
        if "\x00" in curr or "\ufeff" in curr:
            curr = curr.replace("\x00", "").replace("\ufeff", "")
            if "strip_null" not in applied_steps:
                applied_steps.append("strip_null")

        if curr == prev:
            break

    # Collapse SQL inline comments /**/ to space
    if "/*" in curr:
        collapsed_comments = SQL_COMMENT_RE.sub(" ", curr)
        if collapsed_comments != curr:
            applied_steps.append("collapse_comments")
            curr = collapsed_comments

    # Collapse whitespace runs to a single space
    if "  " in curr or "\t" in curr or "\n" in curr or "\r" in curr:
        collapsed_ws = WHITESPACE_RUN_RE.sub(" ", curr)
        if collapsed_ws != curr:
            applied_steps.append("collapse_whitespace")
            curr = collapsed_ws

    if curr not in seen_texts:
        variants.append(Variant(text=curr, chain=list(applied_steps)))
        seen_texts.add(curr)

    # Base64 inspection (bounded search over first 10,000 chars)
    search_target = raw[:10000]
    for match in BASE64_TOKEN_RE.finditer(search_target):
        token = match.group(0)
        decoded_text = try_decode_base64(token)
        if decoded_text and decoded_text not in seen_texts:
            b64_chain = ["base64_decode"]
            variants.append(Variant(text=decoded_text, chain=b64_chain))
            seen_texts.add(decoded_text)

            # Iteratively normalize the decoded string as well
            sub_variants = normalize_string(decoded_text)
            for sub in sub_variants:
                if sub.text not in seen_texts:
                    variants.append(
                        Variant(
                            text=sub.text,
                            chain=["base64_decode"] + sub.chain,
                        )
                    )
                    seen_texts.add(sub.text)

    return variants


def flatten_json(
    data: Any,
    prefix: str = "",
    max_depth: int = 32,
    current_depth: int = 0,
) -> list[tuple[str, str]]:
    """
    Recursively flatten JSON structure into (type, text) pairs.
    Inspects BOTH keys and primitive values.
    Includes max_depth guard against recursion exhaustion attacks.
    """
    items: list[tuple[str, str]] = []
    if current_depth >= max_depth:
        return items

    if isinstance(data, dict):
        for k, v in data.items():
            k_str = str(k)
            items.append(("key", k_str))
            if isinstance(v, (dict, list)):
                items.extend(
                    flatten_json(
                        v,
                        prefix=f"{prefix}{k_str}.",
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                    )
                )
            else:
                items.append(("value", str(v) if v is not None else ""))
    elif isinstance(data, list):
        for idx, elem in enumerate(data):
            if isinstance(elem, (dict, list)):
                items.extend(
                    flatten_json(
                        elem,
                        prefix=f"{prefix}[{idx}].",
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                    )
                )
            else:
                items.append(("value", str(elem) if elem is not None else ""))
    return items


def build_targets(ctx: RequestContext) -> dict[str, list[Variant]]:
    """
    Extract and normalize inspection targets from RequestContext:
    - path: request path
    - query: raw query + individual parameter names and values
    - body: raw body text + recursively extracted JSON/form keys and values
    - headers: header values
    - ua: user agent string
    """
    targets: dict[str, list[Variant]] = {
        "path": [],
        "query": [],
        "body": [],
        "headers": [],
        "ua": [],
    }

    def add_variants(target: str, raw_text: str) -> None:
        if not raw_text:
            return
        produced = normalize_string(raw_text)
        seen = {v.text for v in targets[target]}
        for item in produced:
            if item.text not in seen:
                targets[target].append(item)
                seen.add(item.text)

    # 1. Path
    add_variants("path", ctx.path)

    # 2. Query
    if ctx.query_string:
        add_variants("query", ctx.query_string)
    for q_key, q_vals in ctx.query_params.items():
        add_variants("query", q_key)
        for val in q_vals:
            add_variants("query", val)

    # 3. Body
    if ctx.body_text:
        add_variants("body", ctx.body_text)

    # Parse and extract JSON keys and values if available
    json_obj = ctx.json_body
    if json_obj is None and ctx.body_bytes:
        try:
            json_obj = json.loads(ctx.body_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            json_obj = None

    if json_obj is not None:
        flattened = flatten_json(json_obj)
        for item_type, text in flattened:
            add_variants("body", text)

    # Parse form encoded body if available
    if ctx.form_body:
        for f_key, f_vals in ctx.form_body.items():
            add_variants("body", f_key)
            for f_val in f_vals:
                add_variants("body", f_val)
    elif "application/x-www-form-urlencoded" in ctx.content_type.lower() and ctx.body_text:
        parsed_form = urllib.parse.parse_qs(ctx.body_text, keep_blank_values=True)
        for f_key, f_vals in parsed_form.items():
            add_variants("body", f_key)
            for f_val in f_vals:
                add_variants("body", f_val)

    # 4. Headers
    for h_name, h_val in ctx.headers.items():
        if h_name.lower() != "user-agent":
            add_variants("headers", f"{h_name}: {h_val}")
            add_variants("headers", h_val)

    # 5. User-Agent
    ua_val = ctx.user_agent or ctx.headers.get("user-agent", "")
    targets["ua"] = normalize_string(ua_val)

    return targets
