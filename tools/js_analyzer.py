"""Offline JavaScript source analysis for endpoints and secret-like literals."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

MAX_SOURCE_BYTES = 1_000_000
MAX_ENDPOINTS = 100
MAX_SECRET_MATCHES = 100

_ROUTE_LITERAL = re.compile(
    r"(?P<quote>[\"'`])(?P<value>(?:https?://|/(?:api|graphql|oauth|auth|v\d+(?:/|$)))[^\"'`\s]{0,300})(?P=quote)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>api[_-]?key|client[_-]?secret|access[_-]?token|password|invite[_-]?(?:code|token))\b"
    r"\s*[:=]\s*(?P<quote>[\"'])(?P<value>[^\"']{8,})(?P=quote)"
)
_RECOGNIZABLE_TOKEN = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{16,})\b"
)


def _safe_endpoint(value: str) -> str:
    """Drop query strings, fragments, and userinfo from reported endpoints."""
    if value.lower().startswith(("http://", "https://")):
        try:
            parts = urlsplit(value)
        except ValueError:
            return ""
        if not parts.hostname:
            return ""
        return f"{parts.scheme.lower()}://{parts.hostname.lower()}{parts.path[:300]}"
    return value.split("?", 1)[0].split("#", 1)[0][:300]


def analyze_javascript_source(source: str) -> dict[str, Any]:
    """Analyze caller-provided JavaScript text only; this function makes no requests."""
    if not isinstance(source, str):
        return {"error": "source must be text."}
    encoded = source.encode("utf-8", errors="replace")
    if len(encoded) > MAX_SOURCE_BYTES:
        return {"error": f"source exceeds {MAX_SOURCE_BYTES} bytes."}

    endpoints: list[str] = []
    for match in _ROUTE_LITERAL.finditer(source):
        endpoint = _safe_endpoint(match.group("value"))
        if endpoint and endpoint not in endpoints:
            endpoints.append(endpoint)
        if len(endpoints) >= MAX_ENDPOINTS:
            break

    potential_secrets: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for pattern, kind_group, default_kind in (
        (_SECRET_ASSIGNMENT, "name", "secret_assignment"),
        (_RECOGNIZABLE_TOKEN, None, "recognizable_token"),
    ):
        for match in pattern.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            kind = (match.group(kind_group).lower() if kind_group else default_kind)
            key = (line, kind)
            if key in seen:
                continue
            seen.add(key)
            potential_secrets.append(
                {"line": line, "kind": kind, "value_redacted": True}
            )
            if len(potential_secrets) >= MAX_SECRET_MATCHES:
                break
        if len(potential_secrets) >= MAX_SECRET_MATCHES:
            break

    return {
        "status": "completed",
        "executed": True,
        "network_requests": 0,
        "source_bytes": len(encoded),
        "endpoints": endpoints,
        "potential_secrets": potential_secrets,
        "note": "Potential matches only; secret values are never returned.",
    }
