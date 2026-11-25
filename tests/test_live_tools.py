import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent import Agent
from tools import analyze_javascript_source, execute_tool


class FakeDatabase:
    def recent_context(self):
        return ""

    def add_interaction(self, request, response):
        pass


class LocalEchoServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.observed = []
        self.redirect_sink_hits = 0


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.observed.append((self.path, body))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/sink")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/sink":
            self.server.redirect_sink_hits += 1
        response = b"echo:" + body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format_string, *args):
        pass


class ActiveToolTests(unittest.TestCase):
    def setUp(self):
        self.server = LocalEchoServer(("127.0.0.1", 0), EchoHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def make_agent(self, allowed_urls, approved=True):
        approvals = []

        def approval(name, arguments):
            approvals.append(name)
            return approved

        agent = Agent(
            provider=None,
            db_manager=FakeDatabase(),
            scope={"allowed_urls": allowed_urls},
            approval_callback=approval,
        )
        return agent, approvals

    def test_http_tool_sends_baseline_and_at_most_three_mutations(self):
        url = self.base_url + "/echo"
        agent, approvals = self.make_agent([url])
        args = {
            "url": url,
            "method": "POST",
            "payload_json": json.dumps(
                {"name": "synthetic-user", "age": 31, "role": "viewer", "active": True}
            ),
        }

        result = json.loads(agent._dispatch_tool("mutate_and_fuzz_request", json.dumps(args)))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["request_count"], 4)
        self.assertEqual(len(self.server.observed), 4)
        self.assertEqual(approvals, ["mutate_and_fuzz_request"])
        self.assertTrue(all(path == "/echo" for path, _ in self.server.observed))
        self.assertTrue(all(case.get("status_code") == 200 for case in result["cases"]))
        self.assertTrue(any(case.get("differs_from_baseline") for case in result["cases"][1:]))
        self.assertNotIn("synthetic-user", json.dumps(result))

    def test_out_of_scope_and_unapproved_calls_send_nothing(self):
        url = self.base_url + "/echo"
        args = {"url": url, "method": "POST", "payload_json": '{"id":1}'}
        out_of_scope, approvals = self.make_agent([])
        blocked = json.loads(out_of_scope._dispatch_tool("mutate_and_fuzz_request", json.dumps(args)))
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(approvals, [])
        self.assertEqual(self.server.observed, [])

        denied, approvals = self.make_agent([url], approved=False)
        not_approved = json.loads(denied._dispatch_tool("mutate_and_fuzz_request", json.dumps(args)))
        self.assertEqual(not_approved["status"], "not_authorized")
        self.assertEqual(approvals, ["mutate_and_fuzz_request"])
        self.assertEqual(self.server.observed, [])

    def test_redirect_is_not_followed(self):
        url = self.base_url + "/redirect"
        agent, _ = self.make_agent([url])
        args = {"url": url, "method": "POST", "payload_json": '{"id":1}'}

        result = json.loads(agent._dispatch_tool("mutate_and_fuzz_request", json.dumps(args)))

        self.assertEqual(result["cases"][0]["status_code"], 302)
        self.assertEqual(self.server.redirect_sink_hits, 0)
        self.assertTrue(all(path == "/redirect" for path, _ in self.server.observed))

    def test_direct_dispatch_without_scope_fails_closed(self):
        url = self.base_url + "/echo"
        args = {"url": url, "method": "POST", "payload_json": '{"id":1}'}

        result = json.loads(execute_tool("mutate_and_fuzz_request", args))

        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["executed"])
        self.assertEqual(self.server.observed, [])


class OfflineJavaScriptTests(unittest.TestCase):
    def test_extracts_routes_and_redacts_potential_secrets(self):
        source = """const route = '/api/v1/profile?token=synthetic-value';
const apiKey = 'TEST_SECRET_0123456789';
const next = `https://api.example.test/graphql?access_token=not-for-output`;
"""

        result = analyze_javascript_source(source)
        serialized = json.dumps(result)

        self.assertEqual(result["network_requests"], 0)
        self.assertIn("/api/v1/profile", result["endpoints"])
        self.assertIn("https://api.example.test/graphql", result["endpoints"])
        self.assertEqual(len(result["potential_secrets"]), 1)
        self.assertTrue(result["potential_secrets"][0]["value_redacted"])
        self.assertNotIn("TEST_SECRET_0123456789", serialized)
        self.assertNotIn("not-for-output", serialized)

    def test_rejects_oversized_source(self):
        result = analyze_javascript_source("x" * 1_000_001)
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
