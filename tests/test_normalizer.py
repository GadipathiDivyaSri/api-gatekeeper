"""
Normalizer Unit Tests (Module M3).
Verifies multi-round decoding, HTML unescaping, SQL comment collapsing,
selective Base64 token extraction, and recursive JSON key/value flattening.
"""

from __future__ import annotations

from gateway.models import RequestContext
from gateway.normalizer import (
    Variant,
    build_targets,
    flatten_json,
    normalize_string,
    try_decode_base64,
)


def test_double_url_encoding():
    """Verify that multi-round URL decode unveils nested payloads."""
    # '%2527' -> '%27' -> "'"
    raw = "%2527%2520UNION%2520SELECT"
    variants = normalize_string(raw)
    texts = [v.text for v in variants]
    assert "' UNION SELECT" in texts
    decoded_variant = next(v for v in variants if v.text == "' UNION SELECT")
    assert "url_decode" in decoded_variant.chain


def test_html_entity_unescaping():
    """Verify that HTML entities are unescaped to raw characters."""
    raw = "&lt;script&gt;alert(1)&lt;/script&gt;"
    variants = normalize_string(raw)
    texts = [v.text for v in variants]
    assert "<script>alert(1)</script>" in texts
    decoded_variant = next(v for v in variants if v.text == "<script>alert(1)</script>")
    assert "html_unescape" in decoded_variant.chain


def test_sql_comment_collapsing():
    """Verify that SQL inline comments /**/ and extra whitespace are collapsed."""
    raw = "UNION/**/ALL/**/SELECT"
    variants = normalize_string(raw)
    texts = [v.text for v in variants]
    assert "UNION ALL SELECT" in texts
    decoded_variant = next(v for v in variants if v.text == "UNION ALL SELECT")
    assert "collapse_comments" in decoded_variant.chain


def test_whitespace_collapsing():
    """Verify that multiple whitespace runs are collapsed into single spaces."""
    raw = "SELECT    *    FROM    users"
    variants = normalize_string(raw)
    texts = [v.text for v in variants]
    assert "SELECT * FROM users" in texts


def test_selective_base64_decoding():
    """Verify that Base64 tokens are decoded only when >=12 chars and >=80% printable."""
    # 1. Valid attack payload in Base64: '<script>alert(1)</script>' -> 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
    attack_b64 = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    decoded = try_decode_base64(attack_b64)
    assert decoded == "<script>alert(1)</script>"

    # Full normalizer extraction
    variants = normalize_string(f"data={attack_b64}")
    texts = [v.text for v in variants]
    assert "<script>alert(1)</script>" in texts

    # 2. Binary random garbage should NOT be decoded as printable text
    binary_garbage = "////++++////++++"  # 16 chars of binary bytes
    assert try_decode_base64(binary_garbage) is None

    # 3. Short normal identifier should NOT trigger base64
    short_token = "abcd"
    assert try_decode_base64(short_token) is None


def test_json_key_and_value_flattening():
    """Verify that JSON flattening inspects BOTH keys and primitive values recursively."""
    payload = {
        "$ne": 1,
        "filter": {
            "$gt": 100,
            "query": "admin' OR '1'='1",
        },
        "tags": ["electronics", "$where"],
    }
    flattened = flatten_json(payload)
    types_and_texts = [(t, val) for t, val in flattened]

    # Verify keys are present
    keys = [val for t, val in types_and_texts if t == "key"]
    assert "$ne" in keys
    assert "filter" in keys
    assert "$gt" in keys
    assert "query" in keys
    assert "tags" in keys

    # Verify values are present
    values = [val for t, val in types_and_texts if t == "value"]
    assert "1" in values
    assert "100" in values
    assert "admin' OR '1'='1" in values
    assert "electronics" in values
    assert "$where" in values


def test_build_targets_extraction():
    """Verify that build_targets populates path, query, body, headers, and ua targets."""
    ctx = RequestContext(
        incident_id="AG-TEST-001",
        client_ip="192.0.2.1",
        method="POST",
        path="/api/products/search",
        query_string="category=books&limit=10",
        query_params={"category": ["books"], "limit": ["10"]},
        headers={"content-type": "application/json", "x-attack": "<svg/onload=1>"},
        user_agent="sqlmap/1.5",
        body_bytes=b'{"$ne": 1, "search": "phone"}',
        body_text='{"$ne": 1, "search": "phone"}',
        content_type="application/json",
    )

    targets = build_targets(ctx)

    assert "path" in targets
    assert any("/api/products/search" in v.text for v in targets["path"])

    assert "query" in targets
    assert any("books" in v.text for v in targets["query"])
    assert any("category=books&limit=10" in v.text for v in targets["query"])

    assert "body" in targets
    assert any("$ne" in v.text for v in targets["body"])
    assert any("phone" in v.text for v in targets["body"])

    assert "headers" in targets
    assert any("<svg/onload=1>" in v.text for v in targets["headers"])

    assert "ua" in targets
    assert any("sqlmap/1.5" in v.text for v in targets["ua"])
