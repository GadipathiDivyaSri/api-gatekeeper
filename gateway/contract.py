"""
OpenAPI Contract Guard Module (Module M8).
Enforces a positive security model using backend OpenAPI 3.x specifications:
- Endpoint allow-listing & method enforcement (CONTRACT-UNKNOWN-ENDPOINT)
- Strict query parameter validation (CONTRACT-UNKNOWN-PARAM)
- Schema type/format enforcement (CONTRACT-SCHEMA)
- Mass assignment & sensitive field injection guard (CONTRACT-EXTRA-FIELD, CONTRACT-SENSITIVE-FIELD)
- String size bounds enforcement (CONTRACT-OVERSIZE)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any
import httpx
from jsonschema import Draft202012Validator

from gateway.config import GatewayConfig, get_config
from gateway.models import Finding, RequestContext


logger = logging.getLogger("gatekeeper.contract")


def dereference_schema(schema: Any, root: dict[str, Any], seen: set[str] | None = None) -> Any:
    """Recursively dereference local JSON pointers (#/components/schemas/...) in an OpenAPI schema."""
    if seen is None:
        seen = set()

    if isinstance(schema, dict):
        if "$ref" in schema:
            ref = schema["$ref"]
            if ref in seen:
                return {}  # Guard against circular definitions
            seen.add(ref)
            if ref.startswith("#/"):
                parts = ref[2:].split("/")
                curr = root
                try:
                    for p in parts:
                        curr = curr[p]
                    return dereference_schema(curr, root, seen)
                except (KeyError, TypeError):
                    logger.warning("Unresolvable OpenAPI $ref pointer: %s", ref)
                    return {}
        return {k: dereference_schema(v, root, seen.copy()) for k, v in schema.items()}
    elif isinstance(schema, list):
        return [dereference_schema(item, root, seen.copy()) for item in schema]
    return schema


class OperationContract:
    """Contract specifications for a specific HTTP method on a path."""

    def __init__(
        self,
        method: str,
        operation_dict: dict[str, Any],
        root_spec: dict[str, Any],
    ) -> None:
        self.method = method.upper()
        self.operation_id = operation_dict.get("operationId", "")

        # Extract parameters (query, path, header)
        self.query_params: dict[str, dict[str, Any]] = {}
        self.path_params: dict[str, dict[str, Any]] = {}
        self.declared_params = False

        params_list = operation_dict.get("parameters", [])
        if params_list:
            self.declared_params = True
            for param in params_list:
                p_deref = dereference_schema(param, root_spec)
                p_in = p_deref.get("in")
                p_name = p_deref.get("name")
                p_schema = p_deref.get("schema", {})
                if p_in == "query" and p_name:
                    self.query_params[p_name] = p_schema
                elif p_in == "path" and p_name:
                    self.path_params[p_name] = p_schema

        # Extract requestBody schema
        self.request_body_schema: dict[str, Any] | None = None
        self.body_validator: Draft202012Validator | None = None
        req_body = operation_dict.get("requestBody")
        if req_body:
            rb_deref = dereference_schema(req_body, root_spec)
            content = rb_deref.get("content", {})
            # Look for JSON schema
            json_content = content.get("application/json") or content.get("*/*")
            if json_content and "schema" in json_content:
                self.request_body_schema = json_content["schema"]
                try:
                    self.body_validator = Draft202012Validator(self.request_body_schema)
                except Exception as exc:
                    logger.warning("Failed to create jsonschema validator: %s", exc)


class RouteContract:
    """Compiled route template matching regex and its operations."""

    def __init__(self, path_template: str, path_dict: dict[str, Any], root_spec: dict[str, Any]) -> None:
        self.path_template = path_template

        # Compile path template into regex
        # E.g. /api/products/{product_id} -> ^/api/products/(?P<product_id>[^/]+)$
        pattern = "^"
        last_idx = 0
        self.param_names: list[str] = []

        for match in re.finditer(r"\{([a-zA-Z0-9_]+)\}", path_template):
            pattern += re.escape(path_template[last_idx : match.start()])
            param_name = match.group(1)
            self.param_names.append(param_name)
            pattern += f"(?P<{param_name}>[^/]+)"
            last_idx = match.end()

        pattern += re.escape(path_template[last_idx:]) + "$"
        self.regex = re.compile(pattern)

        # Parse operations (get, post, put, delete, patch, etc.)
        self.operations: dict[str, OperationContract] = {}
        for method_key, op_dict in path_dict.items():
            if method_key.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                self.operations[method_key.upper()] = OperationContract(method_key, op_dict, root_spec)

    def match(self, path: str) -> dict[str, str] | None:
        """Return captured path parameters dict if path matches, else None."""
        m = self.regex.match(path)
        if m:
            return m.groupdict()
        return None


class ContractManager:
    """Manages OpenAPI document loading, path routing, and contract validation."""

    def __init__(
        self,
        config: GatewayConfig | None = None,
        spec: dict[str, Any] | None = None,
    ) -> None:
        self.config = config or get_config()
        self.is_active = False
        self.routes: list[RouteContract] = []
        self.raw_spec: dict[str, Any] | None = None

        if spec is not None:
            self._apply_spec(spec)
        else:
            self.reload()

    def _apply_spec(self, spec: dict[str, Any]) -> bool:
        """Parse OpenAPI specification dictionary and build route contracts."""
        try:
            paths = spec.get("paths", {})
            new_routes: list[RouteContract] = []

            for path_template, path_dict in paths.items():
                if isinstance(path_dict, dict):
                    new_routes.append(RouteContract(path_template, path_dict, spec))

            # Sort routes: exact paths first, templated paths second
            new_routes.sort(key=lambda r: ("{" in r.path_template, -len(r.path_template)))

            self.routes = new_routes
            self.raw_spec = spec
            self.is_active = True
            logger.info("OpenAPI Contract Guard initialized with %d path templates", len(self.routes))
            return True
        except Exception as exc:
            logger.error("Failed to parse OpenAPI document: %s", exc)
            self.is_active = False
            return False

    def load_from_source(self) -> dict[str, Any] | None:
        """Fetch or load OpenAPI document according to OPENAPI_SOURCE config."""
        source = self.config.openapi_source.strip()

        # 1. Local file path
        local_path = Path(source)
        if local_path.is_file():
            try:
                with open(local_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logger.warning("Failed to read local OpenAPI file '%s': %s", local_path, exc)

        # 2. Upstream or HTTP URL
        target_url = source
        if source == "upstream":
            target_url = f"{self.config.upstream_url.rstrip('/')}/openapi.json"

        if target_url.startswith(("http://", "https://")):
            try:
                with httpx.Client(timeout=3.0) as client:
                    resp = client.get(target_url)
                    if resp.status_code == 200:
                        return resp.json()
                    logger.warning("Upstream returned HTTP %d for OpenAPI spec at %s", resp.status_code, target_url)
            except Exception as exc:
                logger.warning("Contract Guard: Failed to fetch OpenAPI spec from %s (%s)", target_url, exc)

        return None

    def reload(self) -> bool:
        """Reload OpenAPI document. Fails open with warning if unavailable."""
        if not self.config.contract.enabled:
            self.is_active = False
            return False

        spec_data = self.load_from_source()
        if spec_data:
            return self._apply_spec(spec_data)

        logger.warning("Contract Guard: OpenAPI spec unavailable, failing open (contract_active=false)")
        self.is_active = False
        return False

    def match_route(self, path: str) -> tuple[RouteContract | None, dict[str, str]]:
        """Find the matching RouteContract and return extracted path parameters."""
        for route in self.routes:
            params = route.match(path)
            if params is not None:
                return route, params
        return None, {}

    def validate(self, ctx: RequestContext) -> list[Finding]:
        """
        Validate incoming request context against positive OpenAPI contract.
        Returns list of contract Findings.
        """
        if not self.is_active or not self.config.contract.enabled:
            return []

        # Exempt Gatekeeper internal control plane and static paths
        if ctx.path == "/_gk" or ctx.path.startswith("/_gk/"):
            return []

        findings: list[Finding] = []

        # 1. Route & Endpoint Match
        route, path_params = self.match_route(ctx.path)
        if route is None:
            findings.append(
                Finding(
                    layer="contract",
                    rule_id="CONTRACT-UNKNOWN-ENDPOINT",
                    name="Unknown endpoint",
                    category="contract",
                    score=5,
                    matched=f"{ctx.method} {ctx.path}",
                    target="path",
                    cwe="CWE-1059",
                    owasp="API9:2023",
                    attack="Improper inventory / unknown endpoint",
                    severity="critical",
                )
            )
            return findings

        # 2. HTTP Method Allow-list
        # Allow OPTIONS and HEAD to known paths
        if ctx.method in ("OPTIONS", "HEAD"):
            return []

        operation = route.operations.get(ctx.method)
        if operation is None:
            findings.append(
                Finding(
                    layer="contract",
                    rule_id="CONTRACT-UNKNOWN-ENDPOINT",
                    name="Undefined method for endpoint",
                    category="contract",
                    score=5,
                    matched=f"{ctx.method} {ctx.path}",
                    target="path",
                    cwe="CWE-1059",
                    owasp="API9:2023",
                    attack="Improper inventory / unknown endpoint",
                    severity="critical",
                )
            )
            return findings

        # 3. Path Parameters Validation
        for p_name, p_val in path_params.items():
            p_schema = operation.path_params.get(p_name, {})
            expected_type = p_schema.get("type")
            if expected_type == "integer":
                try:
                    int(p_val)
                except ValueError:
                    findings.append(
                        Finding(
                            layer="contract",
                            rule_id="CONTRACT-SCHEMA",
                            name="Path parameter type violation",
                            category="contract",
                            score=5,
                            matched=f"path param '{p_name}'={p_val} (expected integer)",
                            target="path",
                            cwe="CWE-1284",
                            owasp="API3:2023",
                            attack="Schema validation error (type/format)",
                            severity="critical",
                        )
                    )

        # 4. Query Parameters Validation
        if ctx.query_params:
            for q_name, q_vals in ctx.query_params.items():
                if q_name not in operation.query_params:
                    # Parameter is unknown
                    if self.config.contract.strict_extra_fields:
                        findings.append(
                            Finding(
                                layer="contract",
                                rule_id="CONTRACT-UNKNOWN-PARAM",
                                name="Unknown query parameter",
                                category="contract",
                                score=self.config.contract.unknown_query_param_score,
                                matched=q_name,
                                target="query",
                                cwe="CWE-1059",
                                owasp="API9:2023",
                                attack="Unknown query parameter",
                                severity="low",
                            )
                        )
                else:
                    # Validate parameter value against schema
                    q_schema = operation.query_params[q_name]
                    exp_type = q_schema.get("type")
                    max_len = q_schema.get("maxLength")

                    for val in q_vals:
                        if max_len is not None and len(val) > max_len:
                            findings.append(
                                Finding(
                                    layer="contract",
                                    rule_id="CONTRACT-OVERSIZE",
                                    name="Oversized query parameter",
                                    category="contract",
                                    score=3,
                                    matched=f"query param '{q_name}' length {len(val)} > {max_len}",
                                    target="query",
                                    cwe="CWE-1284",
                                    owasp="API3:2023",
                                    attack="Oversized string vs maxLength",
                                    severity="medium",
                                )
                            )
                        if exp_type == "integer":
                            try:
                                int(val)
                            except ValueError:
                                findings.append(
                                    Finding(
                                        layer="contract",
                                        rule_id="CONTRACT-SCHEMA",
                                        name="Query parameter type violation",
                                        category="contract",
                                        score=5,
                                        matched=f"query param '{q_name}'={val} (expected integer)",
                                        target="query",
                                        cwe="CWE-1284",
                                        owasp="API3:2023",
                                        attack="Schema validation error (type/format)",
                                        severity="critical",
                                    )
                                )
                        elif exp_type == "number":
                            try:
                                float(val)
                            except ValueError:
                                findings.append(
                                    Finding(
                                        layer="contract",
                                        rule_id="CONTRACT-SCHEMA",
                                        name="Query parameter type violation",
                                        category="contract",
                                        score=5,
                                        matched=f"query param '{q_name}'={val} (expected number)",
                                        target="query",
                                        cwe="CWE-1284",
                                        owasp="API3:2023",
                                        attack="Schema validation error (type/format)",
                                        severity="critical",
                                    )
                                )
                        elif exp_type == "boolean":
                            if val.lower() not in ("true", "false", "1", "0"):
                                findings.append(
                                    Finding(
                                        layer="contract",
                                        rule_id="CONTRACT-SCHEMA",
                                        name="Query parameter boolean format violation",
                                        category="contract",
                                        score=5,
                                        matched=f"query param '{q_name}'={val} (expected boolean)",
                                        target="query",
                                        cwe="CWE-1284",
                                        owasp="API3:2023",
                                        attack="Schema validation error (type/format)",
                                        severity="critical",
                                    )
                                )

        # 5. Request Body Validation
        if ctx.body_text and operation.request_body_schema is not None:
            if ctx.json_body is not None:
                # Check for extra & sensitive fields on JSON objects
                if isinstance(ctx.json_body, dict):
                    declared_props = operation.request_body_schema.get("properties", {})
                    sensitive_set = {s.lower() for s in self.config.contract.sensitive_fields}

                    for field_name in ctx.json_body.keys():
                        if field_name not in declared_props:
                            if field_name.lower() in sensitive_set:
                                findings.append(
                                    Finding(
                                        layer="contract",
                                        rule_id="CONTRACT-SENSITIVE-FIELD",
                                        name="Injected sensitive field",
                                        category="contract",
                                        score=5,
                                        matched=f"sensitive field '{field_name}' in body",
                                        target="body",
                                        cwe="CWE-915",
                                        owasp="API3:2023",
                                        attack="Mass assignment (sensitive field injection)",
                                        severity="critical",
                                    )
                                )
                            elif self.config.contract.strict_extra_fields:
                                findings.append(
                                    Finding(
                                        layer="contract",
                                        rule_id="CONTRACT-EXTRA-FIELD",
                                        name="Extra undeclared body field",
                                        category="contract",
                                        score=3,
                                        matched=f"extra field '{field_name}' in body",
                                        target="body",
                                        cwe="CWE-915",
                                        owasp="API3:2023",
                                        attack="Mass assignment (extra body field)",
                                        severity="medium",
                                    )
                                )

                # Validate with Draft202012Validator
                if operation.body_validator:
                    for err in operation.body_validator.iter_errors(ctx.json_body):
                        if err.validator == "maxLength":
                            findings.append(
                                Finding(
                                    layer="contract",
                                    rule_id="CONTRACT-OVERSIZE",
                                    name="Oversized body field string",
                                    category="contract",
                                    score=3,
                                    matched=err.message,
                                    target="body",
                                    cwe="CWE-1284",
                                    owasp="API3:2023",
                                    attack="Oversized string vs maxLength",
                                    severity="medium",
                                )
                            )
                        elif err.validator in ("type", "required", "format", "minimum", "maximum", "minLength", "pattern"):
                            findings.append(
                                Finding(
                                    layer="contract",
                                    rule_id="CONTRACT-SCHEMA",
                                    name="Body schema validation error",
                                    category="contract",
                                    score=5,
                                    matched=err.message,
                                    target="body",
                                    cwe="CWE-1284",
                                    owasp="API3:2023",
                                    attack="Schema validation error (type/format)",
                                    severity="critical",
                                )
                            )
            elif ctx.content_type.startswith("application/json"):
                # Content-Type was application/json but body could not be parsed as valid JSON
                findings.append(
                    Finding(
                        layer="contract",
                        rule_id="CONTRACT-SCHEMA",
                        name="Malformed JSON body",
                        category="contract",
                        score=5,
                        matched="Invalid JSON syntax",
                        target="body",
                        cwe="CWE-1284",
                        owasp="API3:2023",
                        attack="Schema validation error (type/format)",
                        severity="critical",
                    )
                )

        return findings
