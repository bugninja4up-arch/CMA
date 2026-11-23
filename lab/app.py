"""Loopback-only synthetic multi-tenant SaaS lab for CMA integration tests."""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from typing import Any

LAB_MARKER = "synthetic-v1"
MAX_BODY_BYTES = 16 * 1024

# Public test fixture only. These values and records are fabricated and disposable.
APP_JS = '''// Synthetic CMA lab frontend fixture.
const acceptEndpoint = "/api/v1/invitations/accept";
const invite_code = "SYNTHETIC-AURORA-ATTACK-001";
async function acceptInvitation(role) {
  return fetch(acceptEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ invite_code, role })
  });
}
'''


class LabState:
    """In-memory seeded users, invitations, and memberships for one test run."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.actors = {
            "owner": {"email": "owner@aurora.test"},
            "viewer": {"email": "viewer@aurora.test"},
            "attacker": {"email": "analyst@aurora.test"},
            "control": {"email": "engineer@northstar.test"},
            "outsider": {"email": "outsider@northstar.test"},
        }
        self.invitations = {
            "SYNTHETIC-AURORA-ATTACK-001": {
                "email": "analyst@aurora.test",
                "tenant": "aurora",
                "role": "viewer",
                "consumed": False,
            },
            "SYNTHETIC-AURORA-CONTROL-001": {
                "email": "viewer@aurora.test",
                "tenant": "aurora",
                "role": "viewer",
                "consumed": False,
            },
            "SYNTHETIC-NORTHSTAR-CONTROL-001": {
                "email": "engineer@northstar.test",
                "tenant": "northstar",
                "role": "viewer",
                "consumed": False,
            },
            "SYNTHETIC-AURORA-MISMATCH-001": {
                "email": "analyst@aurora.test",
                "tenant": "aurora",
                "role": "viewer",
                "consumed": False,
            },
        }
        self.memberships = {("owner", "aurora"): "owner"}


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int = 0) -> None:
        # Do not accept a configurable host: this lab must never bind externally.
        super().__init__(("127.0.0.1", port), LabRequestHandler)
        self.lab_state = LabState()


class LabRequestHandler(BaseHTTPRequestHandler):
    server_version = "CMASyntheticLab/1.0"
    sys_version = ""

    @property
    def state(self) -> LabState:
        return self.server.lab_state  # type: ignore[attr-defined]

    def log_message(self, format_string: str, *args: Any) -> None:
        # Avoid writing request data to logs; all fixtures are disposable.
        return

    def _respond(self, status: int, data: dict[str, Any], evidence: str) -> None:
        encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-CMA-Lab", LAB_MARKER)
        self.send_header("X-CMA-Lab-Evidence", evidence)
        self.end_headers()
        self.wfile.write(encoded)

    def _respond_js(self) -> None:
        encoded = APP_JS.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-CMA-Lab", LAB_MARKER)
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._respond(400, {"error": "invalid_content_length"}, "request:invalid_length")
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._respond(413, {"error": "request_too_large"}, "request:too_large")
            return None
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {"error": "invalid_json"}, "request:invalid_json")
            return None
        if not isinstance(value, dict):
            self._respond(400, {"error": "json_object_required"}, "request:object_required")
            return None
        return value

    def _actor(self) -> tuple[str | None, str | None]:
        actor = self.headers.get("X-CMA-Lab-Actor", "")
        if not actor:
            return None, "identity:required"
        if actor not in self.state.actors:
            return None, "identity:unknown"
        return actor, None

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._respond(200, {"status": "ok", "lab": LAB_MARKER}, "health:ok")
            return
        if path == "/static/app.js":
            self._respond_js()
            return

        export_match = re.fullmatch(r"/api/v1/tenants/([a-z0-9-]+)/billing/export", path)
        if not export_match:
            self._respond(404, {"error": "not_found"}, "route:not_found")
            return
        actor, error_evidence = self._actor()
        if actor is None:
            self._respond(401, {"error": "authentication_required"}, error_evidence or "identity:required")
            return
        tenant = export_match.group(1)
        with self.state.lock:
            role = self.state.memberships.get((actor, tenant))
        if role not in {"owner", "billing_admin"}:
            self._respond(403, {"error": "permission_denied"}, "billing-export:denied")
            return
        tenant_label = "Aurora Labs" if tenant == "aurora" else "Northstar Workspace"
        payload = {
            "tenant": tenant_label,
            "export_id": f"SYNTHETIC-{tenant.upper()}-EXPORT-001",
            "rows": [
                {
                    "invoice_id": f"SYNTHETIC-{tenant.upper()}-INVOICE-001",
                    "amount_usd": 1250.00,
                    "billing_contact": f"billing@{tenant}.test",
                }
            ],
        }
        self._respond(200, payload, "billing-export:authorized:synthetic")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        body = self._read_json()
        if body is None:
            return
        if path != "/api/v1/invitations/accept":
            self._respond(404, {"error": "not_found"}, "route:not_found")
            return

        actor, error_evidence = self._actor()
        if actor is None:
            self._respond(401, {"error": "authentication_required"}, error_evidence or "identity:required")
            return
        if set(body) != {"invite_code", "role"}:
            self._respond(400, {"error": "invite_code_and_role_required"}, "invite:invalid_request")
            return
        invite_code = body.get("invite_code")
        requested_role = body.get("role")
        if not isinstance(invite_code, str) or not isinstance(requested_role, str):
            self._respond(400, {"error": "string_fields_required"}, "invite:invalid_request")
            return
        if requested_role not in {"viewer", "billing_admin"}:
            self._respond(400, {"error": "unsupported_role"}, "invite:invalid_role")
            return

        with self.state.lock:
            invitation = self.state.invitations.get(invite_code)
            if invitation is None:
                self._respond(404, {"error": "invitation_not_found"}, "invite:not_found")
                return
            if invitation["consumed"]:
                self._respond(409, {"error": "invitation_already_used"}, "invite:already_used")
                return
            if invitation["email"] != self.state.actors[actor]["email"]:
                self._respond(403, {"error": "recipient_mismatch"}, "invite:recipient_mismatch")
                return

            tenant = str(invitation["tenant"])
            # Aurora deliberately models a vulnerable implementation: it trusts
            # the role supplied by the invitee instead of the role stored in the
            # invitation. Northstar is the patched negative-control tenant.
            effective_role = requested_role if tenant == "aurora" else str(invitation["role"])
            invitation["consumed"] = True
            self.state.memberships[(actor, tenant)] = effective_role

        evidence = f"membership:{tenant}:{effective_role}"
        self._respond(
            201,
            {"status": "accepted", "tenant": tenant, "role": effective_role},
            evidence,
        )


def create_lab_server(port: int = 0) -> LabHTTPServer:
    """Create a disposable lab server bound exclusively to IPv4 loopback."""
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")
    return LabHTTPServer(port)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start the loopback-only synthetic CMA SaaS lab.")
    parser.add_argument("--port", type=int, default=8765, help="TCP port; use 0 for an ephemeral port")
    args = parser.parse_args()
    server = create_lab_server(args.port)
    host, port = server.server_address
    print(f"Synthetic lab listening only on http://{host}:{port}")
    print("No external targets or real user data are used; press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("Stopping synthetic lab.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
