from __future__ import annotations

import http.client
import json
import threading
import unittest

from labs.local_web_lab.server import LocalLabServer, MAX_POST_BYTES, allowed_urls_for_port
from tools.browser_engine import inspect_page
from tools.differential_engine import mutate_and_fuzz_request
from tools.js_analyzer import analyze_javascript_source
from tools.recon_engine import crawl_site


_RED_SESSION = "lab-session-tenant-red-analyst"


class LocalWebLabTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalLabServer(0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.port = self.server.server_port
        self.base = f"http://127.0.0.1:{self.port}"
        self.scope_urls = allowed_urls_for_port(self.port)
        self.scope = {"allowed_urls": self.scope_urls}

    def _stop_server(self):
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), "local lab server thread did not stop")

    def request(self, method: str, route: str, body: bytes | None = None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, route, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_server_is_loopback_bound_and_scope_is_exact_and_complete(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertEqual(self.server.server_address[1], self.port)
        self.assertTrue(self.scope_urls)
        self.assertEqual(len(self.scope_urls), len(set(self.scope_urls)))
        self.assertTrue(all(url.startswith(f"http://127.0.0.1:{self.port}/") for url in self.scope_urls))
        self.assertIn(self.base + "/api/exports/export-blue-q4", self.scope_urls)
        self.assertIn(self.base + "/api/reports/blue-q4", self.scope_urls)
        self.assertNotIn(self.base.replace("127.0.0.1", "localhost") + "/", self.scope_urls)

    def test_chain_confirms_cross_tenant_export_and_report_access_without_token_in_evidence(self):
        # A real target would derive this principal from its authenticated
        # session; the lab uses a fixed, explicitly fake local bearer session.
        red_headers = {"Authorization": f"Bearer {_RED_SESSION}"}
        status_no_session, _, _ = self.request("GET", "/api/exports/export-blue-q4")
        self.assertEqual(status_no_session, 401)

        export_status, export_headers, export_body = self.request(
            "GET", "/api/exports/export-blue-q4", headers=red_headers
        )
        self.assertEqual(export_status, 200)
        self.assertTrue(export_headers["Content-Type"].startswith("application/json"))
        self.assertNotIn("Set-Cookie", export_headers)
        export = json.loads(export_body)
        integration = export["integration"]
        self.assertEqual(export["tenant_id"], "tenant-blue")
        self.assertEqual(integration["authorization_scheme"], "Bearer")
        integration_token = integration["bearer_token"]
        self.assertIsInstance(integration_token, str)
        self.assertIn("FAKE", integration_token)

        # The red tenant is supplied as the requested report tenant, but the
        # downstream endpoint checks only the fake integration token and
        # returns the blue report. No credential is copied into response data.
        report_status, _, report_body = self.request(
            "POST",
            "/api/reports/blue-q4",
            json.dumps({"tenant_id": "tenant-red"}).encode("utf-8"),
            {"Authorization": f"Bearer {integration_token}", "Content-Type": "application/json"},
        )
        self.assertEqual(report_status, 200)
        report = json.loads(report_body)
        self.assertEqual(report["tenant_id"], "tenant-blue")
        self.assertEqual(report["report_id"], "blue-q4")

        # This is the sanitized evidence shape appropriate for a finding or
        # attack-chain matrix; never include the raw export or token value.
        evidence = {
            "step_1": {"actor_tenant": "tenant-red", "role": "analyst", "status": export_status},
            "step_2": {"object_tenant": export["tenant_id"], "export_id": export["export_id"], "credential": "[REDACTED]"},
            "step_3": {"requested_tenant": "tenant-red", "returned_tenant": report["tenant_id"], "status": report_status},
        }
        serialized_evidence = json.dumps(evidence, sort_keys=True)
        self.assertFalse(integration_token in serialized_evidence, "sanitized evidence contains a sensitive value")
        self.assertNotIn("bearer_token", serialized_evidence)

    def test_routes_are_deterministic_and_only_use_synthetic_data(self):
        for route, marker in (
            ("/", b"LOCAL TRAINING LAB"),
            ("/lab/saas", b"tenant-blue"),
            ("/lab/forms", b'action="/api/type-check"'),
            ("/lab/about", b"127.0.0.1"),
            ("/static/lab.js", b"FAKE_LOCAL_ANALYZER_KEY"),
            ("/healthz", b'"synthetic_data":true'),
        ):
            with self.subTest(route=route):
                status, headers, body = self.request("GET", route)
                self.assertEqual(status, 200)
                self.assertIn(marker, body)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertNotIn("Set-Cookie", headers)
                status_again, _, body_again = self.request("GET", route)
                self.assertEqual((status_again, body_again), (status, body))

        status, _, _ = self.request("GET", "/not-a-route")
        self.assertEqual(status, 404)
        status, _, _ = self.request("PATCH", "/lab/about")
        self.assertEqual(status, 405)
        status, _, _ = self.request("GET", "/api/reports/blue-q4")
        self.assertEqual(status, 405)

    def test_type_check_is_deterministic_and_post_body_is_bounded(self):
        headers = {"Content-Type": "application/json"}
        status, _, body = self.request("POST", "/api/type-check", b'{"age":37}', headers)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"accepted": True, "type": "integer"})
        for value in ('"37"', "null"):
            with self.subTest(value=value):
                status, _, _ = self.request("POST", "/api/type-check", f'{{"age":{value}}}'.encode(), headers)
                self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/type-check", b"x" * (MAX_POST_BYTES + 1), headers)
        self.assertEqual(status, 413)
        status, _, _ = self.request("POST", "/api/type-check", b"not json", headers)
        self.assertEqual(status, 400)

    def test_redirect_is_observed_but_not_followed(self):
        status, headers, _ = self.request("GET", "/lab/redirect")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "/lab/about")
        result = crawl_site(self.base + "/lab/redirect", scope=self.scope)
        self.assertEqual(result["request_count"], 1)
        self.assertEqual([page["url"] for page in result["pages"]], [self.base + "/lab/redirect"])
        self.assertEqual(result["pages"][0]["status_code"], 302)

    def test_crawler_remains_in_exact_scope_and_finds_local_pages(self):
        result = crawl_site(self.base + "/", scope=self.scope, max_pages=5)
        self.assertEqual(result["status"], "completed")
        urls = [page["url"] for page in result["pages"]]
        self.assertLessEqual(result["request_count"], 5)
        self.assertTrue(all(url in self.scope_urls for url in urls))
        self.assertTrue(any(url.endswith("/lab/saas") for url in urls))
        self.assertTrue(any(url.endswith("/lab/forms") for url in urls))
        self.assertTrue(any(url.endswith("/lab/about") for url in urls))
        self.assertTrue(all("127.0.0.1" in url for url in urls))

    def test_differential_engine_confirms_integer_to_string_status_change(self):
        result = mutate_and_fuzz_request(
            self.base + "/api/type-check", "POST", '{"age":37}', scope=self.scope
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(result["cases"][0]["status_code"], 200)
        self.assertEqual(result["cases"][1]["status_code"], 400)
        self.assertTrue(result["cases"][1]["differs_from_baseline"])

    def test_js_analyzer_finds_synthetic_routes_and_redacts_fake_key(self):
        status, _, body = self.request("GET", "/static/lab.js")
        self.assertEqual(status, 200)
        result = analyze_javascript_source(body.decode("utf-8"))
        self.assertEqual(result["network_requests"], 0)
        self.assertIn("/api/exports/export-blue-q4", result["endpoints"])
        self.assertTrue(result["potential_secrets"])
        self.assertTrue(all(item["value_redacted"] for item in result["potential_secrets"]))
        self.assertNotIn("FAKE_LOCAL_ANALYZER_KEY", json.dumps(result))

    def test_inspect_page_reads_metadata_without_values_when_browser_available(self):
        try:
            from tools.browser_engine import _launch_options, _load_playwright

            sync_playwright = _load_playwright()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**_launch_options())
                browser.close()
        except Exception as exc:
            self.skipTest(f"Playwright and Chromium are not both available: {type(exc).__name__}")

        result = inspect_page(self.base + "/lab/forms", scope=self.scope)
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["forms"][0]["action"], "/api/type-check")
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertEqual(result["forms"][0]["inputs"], [{"name": "age", "type": "text"}])
        self.assertNotIn('"37"', json.dumps(result))


if __name__ == "__main__":
    unittest.main()
