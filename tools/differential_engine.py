"""Bounded HTTP differential checks for explicitly scoped, approved targets."""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

from tools.scope import is_cma_lab_url, is_url_in_scope

MAX_MUTATIONS = 3
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 5
MUTATION_MARKER = "__anomaly_engineer_type_mutation__"
LAB_ACTORS = frozenset({"owner", "viewer", "attacker", "control", "outsider"})
LAB_RESPONSE_MARKER = "synthetic-v1"


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


def _summarize_response(response: Any, url: str) -> dict[str, Any]:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(body) > MAX_RESPONSE_BYTES
    body = body[:MAX_RESPONSE_BYTES]
    headers = response.headers
    summary = {
        "status_code": int(getattr(response, "status", None) or getattr(response, "code", 0)),
        "content_type": str(headers.get("Content-Type", ""))[:100],
        "body_bytes_observed": len(body),
        "body_truncated": truncated,
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    # Only accept a short, non-content evidence label from the explicitly marked
    # synthetic lab on a literal loopback IP. Real response bodies stay redacted.
    if is_cma_lab_url(url) and headers.get("X-CMA-Lab") == LAB_RESPONSE_MARKER:
        evidence = str(headers.get("X-CMA-Lab-Evidence", ""))[:120]
        if re.fullmatch(r"[A-Za-z0-9:_-]{1,120}", evidence):
            summary["lab_evidence"] = evidence
    return summary


def _send_one(
    url: str,
    method: str,
    payload: dict[str, Any],
    lab_actor: str | None = None,
) -> dict[str, Any]:
    body = None
    if method == "POST":
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            return {"error": "request_too_large"}
    headers = {
        "Accept": "*/*",
        "User-Agent": "Anomaly-Engineer/0.1 (bounded security test)",
        "Connection": "close",
    }
    if method == "POST":
        headers["Content-Type"] = "application/json"
    if lab_actor is not None:
        headers["X-CMA-Lab-Actor"] = lab_actor
    request = Request(url, data=body, headers=headers, method=method)
    opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return _summarize_response(response, url)
    except HTTPError as response:
        # HTTP errors, including redirects, are observations; do not follow them.
        return _summarize_response(response, url)
    except (URLError, TimeoutError, OSError) as exc:
        return {"error": type(exc).__name__}


def mutate_and_fuzz_request(
    url: str,
    method: str,
    payload_json: str,
    *,
    scope: dict[str, Any] | None = None,
    baseline_only: bool = False,
    lab_actor: str | None = None,
) -> dict[str, Any]:
    """Send one baseline plus at most three type substitutions to a scoped URL.

    The caller must enforce a human approval step. The optional synthetic lab
    actor is accepted only for literal loopback IP URLs and is not a credential.
    Redirects are refused; bodies, time, and request counts are bounded.
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
    if lab_actor is not None:
        if lab_actor not in LAB_ACTORS:
            return {"status": "invalid_input", "executed": False, "message": "Unknown synthetic lab actor."}
        if not is_cma_lab_url(url):
            return {
                "status": "blocked",
                "executed": False,
                "message": "Synthetic lab identities can only be used on the CMA lab API routes over literal loopback IP URLs.",
            }
    if not isinstance(baseline_only, bool):
        return {"status": "invalid_input", "executed": False, "message": "baseline_only must be a boolean."}
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
    if not isinstance(payload, dict):
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "payload_json must be a JSON object.",
        }
    if method == "POST" and not payload:
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "POST payload_json must be a non-empty JSON object.",
        }
    if method == "GET" and payload:
        return {
            "status": "invalid_input",
            "executed": False,
            "message": "GET requires an empty JSON object: {}.",
        }

    baseline = _send_one(url, method, payload, lab_actor)
    cases = [{"case": "baseline", "mutated_key": None, **baseline}]
    if "error" in baseline:
        return {
            "status": "network_error",
            "executed": True,
            "request_count": 1,
            "cases": cases,
            "message": "The baseline request failed; mutations were not sent.",
        }

    if baseline_only or method == "GET":
        return {
            "status": "completed",
            "executed": True,
            "request_count": 1,
            "maximum_request_count": 1,
            "cases": cases,
            "note": "One baseline request was sent; response bodies are not returned.",
        }

    baseline_fingerprint = (
        baseline.get("status_code"),
        baseline.get("body_bytes_observed"),
        baseline.get("body_sha256"),
    )
    for key, mutated in _mutated_payloads(payload):
        time.sleep(0.2)
        result = _send_one(url, method, mutated, lab_actor)
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
