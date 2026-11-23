"""Run the known synthetic SaaS chain against the CMA lab on IPv4 loopback only."""
from __future__ import annotations

import http.client
import argparse
import json
import re
from typing import Any
from urllib.parse import urlsplit

_MAX_RESPONSE_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 2
_RED_SESSION = "lab-session-tenant-red-analyst"
_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")


def _validate_base_url(base_url: Any) -> tuple[int | None, str | None]:
    """Accept only an explicit plain-HTTP IPv4 loopback origin with a port."""
    if not isinstance(base_url, str) or len(base_url) > 512:
        return None, "base_url must be an HTTP origin on 127.0.0.1 with an explicit port."
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return None, "base_url must be an HTTP origin on 127.0.0.1 with an explicit port."
    if (
        parsed.scheme.lower() != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port is None
        or not 1 <= port <= 65535
    ):
        return None, "Blocked: evaluator only permits http://127.0.0.1:<port> with no path, query, or fragment."
    return port, None


def _request(port: int, method: str, path: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
    """Make one bounded direct-to-loopback HTTP request; never follow redirects."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        response_body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(response_body) > _MAX_RESPONSE_BYTES:
            raise ValueError("Local lab response exceeded the fixed size limit.")
        return response.status, response_headers, response_body
    finally:
        connection.close()


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        result = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def evaluate_local_saas_chain(base_url: str) -> dict[str, Any]:
    """Verify the synthetic cross-tenant export→report chain and return safe evidence.

    The evaluator refuses hostnames, public IPs, IPv6, TLS URLs, credentials in URLs,
    and non-loopback addresses before opening a socket. It issues at most four fixed,
    bounded requests, follows no redirects, stores no state, and never returns the
    fake integration bearer from the lab response. The complete evaluation uses
    at most five fixed requests: health check, two export requests (including a
    negative control), and two report requests (including a negative control).
    """
    port, error = _validate_base_url(base_url)
    if error:
        return {"status": "blocked", "executed": False, "message": error}
    assert port is not None

    try:
        health_status, health_headers, health_body = _request(port, "GET", "/healthz")
        health = _json_object(health_body)
        if (
            health_status != 200
            or health_headers.get("server") != "LocalTrainingLab"
            or not health
            or health.get("status") != "ok"
            or health.get("lab") != "local"
            or health.get("synthetic_data") is not True
        ):
            return {"status": "not_cma_lab", "executed": True, "request_count": 1, "message": "The loopback service did not identify itself as the synthetic CMA lab; no further requests were sent."}

        control_status, _, _ = _request(port, "GET", "/api/exports/export-blue-q4")
        if control_status != 401:
            return {"status": "evaluation_failed", "executed": True, "request_count": 2, "message": "The unauthenticated export control did not return the expected 401."}

        export_status, export_headers, export_body = _request(
            port,
            "GET",
            "/api/exports/export-blue-q4",
            headers={"Authorization": f"Bearer {_RED_SESSION}"},
        )
        export = _json_object(export_body)
        integration = export.get("integration") if export else None
        integration_token = integration.get("bearer_token") if isinstance(integration, dict) else None
        if (
            export_status != 200
            or not export
            or export.get("tenant_id") != "tenant-blue"
            or export.get("export_id") != "export-blue-q4"
            or not isinstance(integration_token, str)
            or not _TOKEN_SHAPE.fullmatch(integration_token)
            or "FAKE" not in integration_token
            or not str(integration.get("notice", "")).startswith("FAKE LOCAL TRAINING VALUE")
            or not export_headers.get("content-type", "").lower().startswith("application/json")
        ):
            return {"status": "evaluation_failed", "executed": True, "request_count": 3, "message": "The local export response did not match the expected synthetic training fixture."}

        unauth_report_status, _, _ = _request(
            port,
            "POST",
            "/api/reports/blue-q4",
            headers={"Content-Type": "application/json"},
            body=b'{"tenant_id":"tenant-red"}',
        )
        if unauth_report_status != 401:
            return {"status": "evaluation_failed", "executed": True, "request_count": 4, "message": "The unauthenticated report control did not return the expected 401."}

        report_status, report_headers, report_body = _request(
            port,
            "POST",
            "/api/reports/blue-q4",
            headers={
                "Authorization": f"Bearer {integration_token}",
                "Content-Type": "application/json",
            },
            body=b'{"tenant_id":"tenant-red"}',
        )
        report = _json_object(report_body)
        if (
            report_status != 200
            or not report
            or report.get("tenant_id") != "tenant-blue"
            or report.get("report_id") != "blue-q4"
            or not report_headers.get("content-type", "").lower().startswith("application/json")
            or integration_token.encode("utf-8") in report_body
        ):
            return {"status": "evaluation_failed", "executed": True, "request_count": 5, "message": "The downstream report response did not match the expected tenant-mismatch fixture."}
    except (OSError, http.client.HTTPException, ValueError, TypeError):
        # Never echo exception text or response bytes; either might contain test data.
        return {"status": "evaluation_failed", "executed": True, "message": "The bounded local evaluation could not complete; sensitive response content was suppressed."}

    findings = [
        {
            "id": "LAB-F1",
            "title": "BOLA: tenant-red analyst reads tenant-blue export",
            "status": "confirmed",
            "summary": "A low-privilege synthetic tenant-red analyst retrieved an export owned by tenant-blue.",
            "preconditions": ["Local CMA synthetic lab is running on 127.0.0.1.", "Synthetic tenant-red analyst session is used."],
            "evidence": [
                "Negative control: the same export route without a session returned HTTP 401.",
                "With the synthetic tenant-red analyst session, GET /api/exports/export-blue-q4 returned HTTP 200 and export tenant_id tenant-blue.",
                "The export contained a clearly labeled synthetic integration bearer; its value was discarded and is not included in evidence.",
            ],
            "verification": {
                "reproduction": {"passed": True, "evidence": [2]},
                "impact": {"passed": True, "evidence": [2]},
                "negative_control": {"passed": True, "evidence": [1]},
            },
            "capability_gain": "Read another tenant's synthetic export and obtain its fake downstream integration credential.",
            "impact": "Cross-tenant disclosure of fabricated export records within the local lab only.",
            "remediation": ["Authorize every export read against the authenticated principal's tenant.", "Do not embed bearer credentials in export data; scope downstream credentials to one tenant and purpose."],
        },
        {
            "id": "LAB-F2",
            "title": "Tenant-unbound integration bearer reads tenant-blue report",
            "status": "confirmed",
            "depends_on": ["LAB-F1"],
            "summary": "The integration credential recovered from the cross-tenant export was accepted for a tenant-red request and returned tenant-blue's report.",
            "preconditions": ["LAB-F1 is reproducible and the local synthetic export yields its fake integration credential."],
            "evidence": [
                "Negative control: POST /api/reports/blue-q4 without authorization returned HTTP 401.",
                "Using the synthetic export's fake bearer with requested tenant_id tenant-red returned HTTP 200.",
                "The response identified tenant_id tenant-blue and report_id blue-q4; the bearer value was not copied to the response or evidence.",
            ],
            "verification": {
                "reproduction": {"passed": True, "evidence": [2]},
                "impact": {"passed": True, "evidence": [3]},
                "negative_control": {"passed": True, "evidence": [1]},
            },
            "capability_gain": "Use the recovered synthetic integration credential to read a second tenant's report.",
            "impact": "A reproducible two-step cross-tenant access chain over synthetic data on loopback only.",
            "remediation": ["Bind every report request to the authenticated tenant and validate tenant_id server-side.", "Use audience-, tenant-, and purpose-scoped short-lived credentials with least privilege."],
        },
    ]
    # Import lazily so tools can expose the evaluator without a package cycle.
    from tools.chain_engine import build_attack_chain_matrix

    matrix = build_attack_chain_matrix(findings)
    if matrix.get("status") != "completed" or matrix.get("confirmed_chain_count") != 1:
        return {"status": "evaluation_failed", "executed": True, "request_count": 5, "message": "The verified local steps could not be represented as the expected explicit-evidence chain."}
    return {
        "status": "completed",
        "executed": True,
        "scope": "http://127.0.0.1 only",
        "request_count": 5,
        "synthetic_data_only": True,
        "matrix": matrix,
        "note": "Reproducible local training result only; not a finding about any live service. Secret values are not retained in the result.",
    }


__all__ = ["evaluate_local_saas_chain"]


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate CMA's synthetic loopback SaaS chain.")
    parser.add_argument("--base-url", required=True, help="Exact local origin, e.g. http://127.0.0.1:8765")
    args = parser.parse_args(argv)
    result = evaluate_local_saas_chain(args.base_url)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
