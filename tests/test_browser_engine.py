import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import tools.browser_engine as browser_engine


class SyntheticPageServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.script_hits = 0
        self.requests = []


class SyntheticPageHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/page")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/large":
            body = b"<html><title>large</title>" + b"x" * (300 * 1024)
            content_type = "text/html; charset=utf-8"
        elif self.path.startswith("/script.js"):
            self.server.script_hits += 1
            body = b"window.synthetic = 'executed';"
            content_type = "application/javascript"
        else:
            body = b'''<!doctype html>
<html><head><title>Synthetic inspection page</title>
<script src="/script.js?script-secret=do-not-fetch"></script></head>
<body>
<a href="/next?link-secret=do-not-return">Next</a>
<form action="/submit?action-secret=do-not-return" method="post">
<input name="account" type="text" value="FORM_VALUE_MUST_NOT_LEAK">
<input name="token" type="hidden" value="HIDDEN_VALUE_MUST_NOT_LEAK">
</form>
</body></html>'''
            content_type = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        pass


class ScopeGateTests(unittest.TestCase):
    def test_out_of_scope_is_rejected_before_playwright_load_or_launch(self):
        with patch.object(browser_engine, "_load_playwright") as load_playwright:
            result = browser_engine.inspect_page(
                "http://127.0.0.1:9/private?secret=value",
                scope={"allowed_urls": []},
            )
        load_playwright.assert_not_called()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["error"], "invalid_or_out_of_scope")
        self.assertEqual(result["request_count"], 0)
        self.assertNotIn("secret", json.dumps(result))

    def test_invalid_url_is_rejected(self):
        with patch.object(browser_engine, "_load_playwright") as load_playwright:
            result = browser_engine.inspect_page("file:///etc/passwd", scope={"allowed_urls": ["file:///etc/passwd"]})
        load_playwright.assert_not_called()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["request_count"], 0)


class BrowserInspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            sync_playwright = browser_engine._load_playwright()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**browser_engine._launch_options())
                browser.close()
        except Exception as exc:
            raise unittest.SkipTest(f"Playwright Chromium is unavailable: {type(exc).__name__}")

    def setUp(self):
        self.server = SyntheticPageServer(("127.0.0.1", 0), SyntheticPageHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_inspects_metadata_without_running_or_fetching_script(self):
        url = self.base_url + "/page?url-secret=must-not-return"
        result = browser_engine.inspect_page(
            url,
            scope={"allowed_urls": [url, self.base_url + "/page"]},
        )

        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["content_type"], "text/html")
        self.assertEqual(result["title"], "Synthetic inspection page")
        self.assertEqual(result["url"], self.base_url + "/page")
        self.assertEqual(result["hrefs"], ["/next"])
        self.assertEqual(result["script_src_paths"], ["/script.js"])
        self.assertEqual(result["forms"][0]["action"], "/submit")
        self.assertEqual(result["forms"][0]["method"], "POST")
        self.assertEqual(
            result["forms"][0]["inputs"],
            [{"name": "account", "type": "text"}, {"name": "token", "type": "hidden"}],
        )
        self.assertEqual(result["request_count"], 1)
        self.assertEqual(result["blocked_browser_resource_count"], 0)
        self.assertEqual(self.server.requests, ["/page"])
        self.assertEqual(self.server.script_hits, 0)
        self.assertIn("JavaScript and page resource requests are blocked", result["note"])
        self.assertIn("forms are never submitted", result["note"])

        serialized = json.dumps(result)
        for private_text in (
            "FORM_VALUE_MUST_NOT_LEAK",
            "HIDDEN_VALUE_MUST_NOT_LEAK",
            "url-secret",
            "link-secret",
            "action-secret",
            "script-secret",
            "do-not-fetch",
        ):
            self.assertNotIn(private_text, serialized)

    def test_redirect_is_reported_and_never_followed(self):
        url = self.base_url + "/redirect"
        result = browser_engine.inspect_page(url, scope={"allowed_urls": [url]})

        self.assertEqual(result["status"], "redirect_not_followed")
        self.assertTrue(result["redirect_seen"])
        self.assertTrue(result["redirect_blocked"])
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(self.server.requests, ["/redirect"])

    def test_response_body_is_capped_at_256_kib(self):
        url = self.base_url + "/large"
        result = browser_engine.inspect_page(url, scope={"allowed_urls": [url]})

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["response_bytes"], 256 * 1024)
        self.assertTrue(result["truncated"])
        self.assertEqual(self.server.requests, ["/large"])


if __name__ == "__main__":
    unittest.main()
