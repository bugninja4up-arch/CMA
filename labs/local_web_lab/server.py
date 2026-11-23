"""Loopback-only synthetic SaaS export/report security-training service."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_POST_BYTES = 16 * 1024
_DEFAULT_PORT = 8765

_ROUTES = (
    "/",
    "/lab/saas",
    "/lab/forms",
    "/lab/about",
    "/lab/redirect",
    "/api/exports/export-blue-q4",
    "/api/reports/blue-q4",
    "/api/type-check",
    "/static/lab.js",
    "/healthz",
)

# These are deliberately fake, local training identities, not usable accounts.
_SESSION_PRINCIPALS = {
    "lab-session-tenant-red-analyst": {"tenant_id": "tenant-red", "role": "analyst"},
    "lab-session-tenant-blue-analyst": {"tenant_id": "tenant-blue", "role": "analyst"},
}
# Intentionally exposed by the vulnerable synthetic export. Never include this
# value in logs, exception text, tool evidence, test output, or report responses.
_FAKE_INTEGRATION_BEARER = "FAKE_LOCAL_CMA_INTEGRATION_BEARER_000000000000"


def allowed_urls_for_port(port: int) -> list[str]:
    """Return exact HTTP scope URLs for every route on this local port only."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    origin = f"http://127.0.0.1:{port}"
    return [origin + route for route in _ROUTES]


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


_LANDING = b'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CMA Local SaaS Lab</title>
<style>body{font:1rem/1.6 system-ui,sans-serif;max-width:54rem;margin:3rem auto;padding:0 1rem;color:#172033;background:#f5f7fb}header,main,nav{padding:1rem 1.4rem;background:white;margin-top:1rem;border-radius:.7rem}header{background:#13233d;color:white}strong{color:#9b321f}a{color:#0758a6}</style></head><body>
<header><strong>LOCAL TRAINING LAB &#8212; synthetic data only</strong><h1>Tenant export and reporting workflow</h1><p>Local-only, disposable SaaS security exercise. The server binds to 127.0.0.1.</p></header>
<nav><h2>Practice pages</h2><ul><li><a href="/lab/saas">Multi-tenant export/report scenario</a></li><li><a href="/lab/forms">JSON type-check exercise</a></li><li><a href="/lab/about">Lab safety and redirect exercise</a></li></ul></nav>
<main><p>All tenants, users, exports, reports, and credentials are fabricated. No real people, services, or data are involved.</p></main></body></html>'''

_SAAS = b'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Local Lab &#8212; SaaS Workflow</title><script src="/static/lab.js"></script></head><body>
<header><strong>LOCAL TRAINING LAB &#8212; synthetic data only</strong></header>
<h1>Tenant export and report workflow</h1>
<p>Scenario: an authenticated, low-privileged tenant-red analyst requests a tenant-blue export. The export object lookup omits owner authorization. The export includes a fake integration bearer credential; the downstream report endpoint accepts it without checking that the requested report tenant matches the credential's tenant.</p>
<p>This intentionally vulnerable chain is local training data only. The export endpoint requires the synthetic red analyst session; the report endpoint consumes the export's synthetic integration credential. Evidence summaries must redact credentials.</p>
<ul><li><a href="/api/exports/export-blue-q4">Synthetic tenant-blue Q4 export (API)</a></li><li><a href="/api/reports/blue-q4">Synthetic tenant-blue Q4 report (API route)</a></li></ul>
<p><a href="/">Home</a> &#183; <a href="/lab/forms">Type-check exercise</a></p></body></html>'''

_FORMS = b'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Local Lab &#8212; Forms</title></head><body>
<header><strong>LOCAL TRAINING LAB &#8212; synthetic data only</strong></header><h1>Type-check form</h1>
<p>Fake values only. The form is not submitted automatically. The differential exercise uses JSON.</p>
<form action="/api/type-check" method="post"><label>Age <input name="age" type="text" value="37"></label><button type="submit">Submit manually to local training endpoint</button></form>
<p><a href="/">Home</a> &#183; <a href="/lab/saas">SaaS workflow</a> &#183; <a href="/lab/about">About</a></p></body></html>'''

_ABOUT = b'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Local Lab &#8212; About</title></head><body>
<header><strong>LOCAL TRAINING LAB &#8212; synthetic data only</strong></header><h1>Isolation and safety</h1>
<p>This server is bound only to 127.0.0.1. No external fetching, command execution, filesystem access, credential collection, persistence, or real target interaction is implemented.</p>
<p><a href="/lab/redirect">Observe a local redirect; clients should not follow it automatically.</a></p>
<p><a href="/">Home</a> &#183; <a href="/lab/saas">SaaS workflow</a></p></body></html>'''

_LAB_JS = b'''// Local synthetic route inventory; the key is conspicuously fake, never a real secret.
const apiKey = "FAKE_LOCAL_ANALYZER_KEY_NOT_A_SECRET_0000";
const routes = ["/api/exports/export-blue-q4", "/api/reports/blue-q4", "/api/type-check"];
void apiKey; void routes;
'''

_EXPORT = {
    "export_id": "export-blue-q4",
    "tenant_id": "tenant-blue",
    "created_by": "synthetic-export-service",
    "period": "2026-Q4",
    "records": [
        {"record_id": "blue-demo-01", "category": "synthetic-usage", "amount": 12},
        {"record_id": "blue-demo-02", "category": "synthetic-storage", "amount": 4},
    ],
    "integration": {
        "name": "synthetic-report-reader",
        "authorization_scheme": "Bearer",
        "bearer_token": _FAKE_INTEGRATION_BEARER,
        "notice": "FAKE LOCAL TRAINING VALUE — not a credential for any real service",
    },
}

_REPORT = {
    "report_id": "blue-q4",
    "tenant_id": "tenant-blue",
    "title": "Synthetic tenant-blue Q4 report",
    "summary": {"synthetic_events": 16, "synthetic_status": "complete"},
}


class _LabHandler(BaseHTTPRequestHandler):
    server_version = "LocalTrainingLab"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format_string: str, *args: object) -> None:
        # Suppress all request logging; the vulnerable export contains a fake token.
        return

    @staticmethod
    def _path(target: str) -> str:
        try:
            return urlsplit(target).path or "/"
        except ValueError:
            return ""

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8", extra_headers: tuple[tuple[str, str], ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        if body and self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _not_found(self) -> None:
        self._send(404, b"Not found.\n")

    def _method_not_allowed(self) -> None:
        self._send(405, b"Method not allowed.\n", extra_headers=(("Allow", "GET, POST"),))

    def _read_json(self) -> tuple[object | None, int | None]:
        if self.headers.get("Transfer-Encoding") is not None:
            return None, 400
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except (TypeError, ValueError):
            return None, 400
        if length < 0:
            return None, 400
        if length > MAX_POST_BYTES:
            return None, 413
        if self.headers.get_content_type().lower() != "application/json":
            return None, 400
        body = self.rfile.read(length)
        if len(body) != length:
            return None, 400
        try:
            return json.loads(body.decode("utf-8")), None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, 400

    def _session_principal(self) -> dict[str, str] | None:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, value = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer":
            return None
        return _SESSION_PRINCIPALS.get(value.strip())

    def do_GET(self) -> None:
        path = self._path(self.path)
        pages = {"/": _LANDING, "/lab/saas": _SAAS, "/lab/forms": _FORMS, "/lab/about": _ABOUT, "/static/lab.js": _LAB_JS}
        if path == "/lab/redirect":
            self._send(302, b"Redirect not followed by design.\n", extra_headers=(("Location", "/lab/about"),))
        elif path == "/healthz":
            self._send(200, b'{"status":"ok","lab":"local","synthetic_data":true}\n', "application/json; charset=utf-8")
        elif path in pages:
            content_type = "application/javascript; charset=utf-8" if path == "/static/lab.js" else "text/html; charset=utf-8"
            self._send(200, pages[path], content_type)
        elif path == "/api/exports/export-blue-q4":
            principal = self._session_principal()
            if principal is None:
                self._send(401, b'{"error":"synthetic_session_required"}\n', "application/json; charset=utf-8", (("WWW-Authenticate", 'Bearer realm="CMA local lab"'),))
            else:
                # Deliberate BOLA: authenticated principal's tenant is not
                # compared with the owner tenant-blue of this export object.
                self._send(200, _json_bytes(_EXPORT), "application/json; charset=utf-8")
        elif path == "/api/reports/blue-q4":
            self._method_not_allowed()
        else:
            self._not_found()

    def do_POST(self) -> None:
        path = self._path(self.path)
        if path not in _ROUTES:
            self._not_found()
            return
        if path not in {"/api/type-check", "/api/reports/blue-q4"}:
            self._method_not_allowed()
            return
        payload, error_status = self._read_json()
        if error_status is not None:
            message = b"Request body too large.\n" if error_status == 413 else b"Invalid JSON request.\n"
            self._send(error_status, message)
            return
        if path == "/api/type-check":
            age = payload.get("age") if isinstance(payload, dict) else None
            if isinstance(age, int) and not isinstance(age, bool):
                self._send(200, b'{"accepted":true,"type":"integer"}\n', "application/json; charset=utf-8")
            else:
                self._send(400, b'{"accepted":false,"expected":"integer"}\n', "application/json; charset=utf-8")
            return

        authorization = self.headers.get("Authorization", "")
        scheme, separator, value = authorization.partition(" ")
        requested_tenant = payload.get("tenant_id") if isinstance(payload, dict) else None
        if not separator or scheme.lower() != "bearer" or value.strip() != _FAKE_INTEGRATION_BEARER:
            self._send(401, b'{"error":"synthetic_integration_token_required"}\n', "application/json; charset=utf-8", (("WWW-Authenticate", 'Bearer realm="CMA local reports"'),))
            return
        if not isinstance(requested_tenant, str) or not requested_tenant:
            self._send(400, b'{"error":"tenant_id_required"}\n', "application/json; charset=utf-8")
            return
        # Deliberate missing tenant binding: this global fake integration token
        # is accepted for a tenant-red request and returns a tenant-blue report.
        # The credential itself is never copied into this response.
        self._send(200, _json_bytes(_REPORT), "application/json; charset=utf-8")

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)


class LocalLabServer(ThreadingHTTPServer):
    """Threading HTTP server hard-bound to IPv4 loopback, never all interfaces."""

    daemon_threads = True
    block_on_close = True

    def __init__(self, port: int = _DEFAULT_PORT):
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError("port must be an integer from 0 to 65535")
        super().__init__(("127.0.0.1", port), _LabHandler, bind_and_activate=True)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start CMA's synthetic SaaS security lab on loopback only.")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT, help="local TCP port (default: 8765; use 0 for an ephemeral port)")
    parser.add_argument("--print-scope", action="store_true", help="print exact allowed_urls JSON for this port and exit")
    args = parser.parse_args(argv)
    if args.print_scope:
        try:
            print(json.dumps({"allowed_urls": allowed_urls_for_port(args.port)}, indent=2))
        except ValueError as exc:
            parser.error(str(exc))
        return 0
    try:
        server = LocalLabServer(args.port)
    except (OSError, ValueError) as exc:
        parser.error(f"could not bind local lab: {exc}")
    port = server.server_port
    print(f"CMA local training lab: http://127.0.0.1:{port}/")
    print("Synthetic data only. Bound to 127.0.0.1; press Ctrl-C to stop.")
    print("Exact CMA scope URLs:")
    print(json.dumps({"allowed_urls": allowed_urls_for_port(port)}, indent=2))
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nStopping local lab...")
    finally:
        server.shutdown()
        server.server_close()
    return 0


__all__ = ["LocalLabServer", "MAX_POST_BYTES", "allowed_urls_for_port"]

if __name__ == "__main__":
    raise SystemExit(_main())
