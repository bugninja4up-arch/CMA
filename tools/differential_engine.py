"""Bounded HTTP differential checks for explicitly scoped, approved targets."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

from tools.scope import is_url_in_scope

MAX_MUTATIONS = 3
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 5
MUTATION_MARKER = "__anomaly_engineer_type_mutation__"


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward a test request to an unapproved redirect destination."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _mutated_payloads(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    results: list[tuple[str, dict[str, Any]]] = []
    for key, value in list(payload.items())[:MAX_MUTATIONS]:
        mutated = dict(payload)
        replacement: Any = None if isinstance(value, str) else MUTATION_MARKER
        mutated[key] = replacement
        results.append((str(key)[:80], mutated))
    return results


def _summarize_response(response: Any) -> dict[str, Any]:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(body) > MAX_RESPONSE_BYTES
    body = body[:MAX_RESPONSE_BYTES]
    headers = response.headers
    return {
        "status_code": int(getattr(response, "status", None) or getattr(response, "code", 0)),
        "content_type": str(headers.get("Content-Type", ""))[:100],
        "body_bytes_observed": len(body),
        "body_truncated": truncated,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def _send_one(url: str, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        return {"error": "request_too_large"}
    request = Request(
        url,
        data=body,
        headers={
            "Accept": "*/*",
            "Content-Type": "application/json",
            "User-Agent": "Anomaly-Engineer/0.1 (bounded security test)",
            "Connection": "close",
        },
        method=method,
    )
    opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return _summarize_response(response)
    except HTTPError as response:
        # HTTP errors, including redirects, are observations; do not follow them.
        return _summarize_response(response)
    except (URLError, TimeoutError, OSError) as exc:
        return {"error": type(exc).__name__}


def mutate_and_fuzz_request(
    url: str,
    method: str,
    payload_json: str,
    *,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send one baseline plus at most three JSON type substitutions.

    The caller must enforce a human approval step. This function also requires
    the configured scope, refuses redirects, sends no cookies or credentials,
    and bounds request size, response size, timeout, and request count.
    """
    if not is_url_in_scope(url, scope):
        return {
            "status": "blocked",
            "executed": False,
            "message": "Target is not in the explicitly configured scope.",
        }
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return {"status": "invalid_input", "executed": False, "message": "Invalid HTTP URL."}
    method = method.strip().upper()
    if method not in {"GET", "POST"}:
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "Only GET and POST are supported.",
        }
    try:
        payload = json.loads(payload_json)
    except (TypeError, json.JSONDecodeError):
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "payload_json must be valid JSON.",
        }
    if not isinstance(payload, dict) or not payload:
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "payload_json must be a non-empty JSON object.",
        }

    baseline = _send_one(url, method, payload)
    cases = [{"case": "baseline", "mutated_key": None, **baseline}]
    if "error" in baseline:
        return {
            "status": "network_error",
            "executed": True,
            "request_count": 1,
            "cases": cases,
            "message": "The baseline request failed; mutations were not sent.",
        }

    baseline_fingerprint = (
        baseline.get("status_code"),
        baseline.get("body_bytes_observed"),
        baseline.get("body_sha256"),
    )
    for key, mutated in _mutated_payloads(payload):
        time.sleep(0.2)
        result = _send_one(url, method, mutated)
        case = {"case": "type_mutation", "mutated_key": key, **result}
        if "error" not in result:
            fingerprint = (
                result.get("status_code"),
                result.get("body_bytes_observed"),
                result.get("body_sha256"),
            )
            case["differs_from_baseline"] = fingerprint != baseline_fingerprint
        cases.append(case)

    return {
        "status": "completed",
        "executed": True,
        "request_count": len(cases),
        "maximum_request_count": MAX_MUTATIONS + 1,
        "cases": cases,
        "note": "Response bodies are not returned; differences are fingerprints only.",
    }
