import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tools.recon_engine import crawl_site


class SyntheticServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, routes):
        super().__init__(address, handler)
        self.routes = routes
        self.requests = []


class SyntheticHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        status, headers, body = self.server.routes.get(
            self.path.split("?", 1)[0], (404, {"Content-Type": "text/plain"}, b"not found")
        )
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, format_string, *args):
        pass


class ReconCrawlerTests(unittest.TestCase):
    def setUp(self):
        self.servers = []

    def tearDown(self):
        for server, thread in reversed(self.servers):
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def make_server(self, routes):
        server = SyntheticServer(("127.0.0.1", 0), SyntheticHandler, routes)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return server, f"http://127.0.0.1:{server.server_port}"

    @staticmethod
    def allow(*urls):
        return {"allowed_urls": list(urls)}

    def test_crawls_in_scope_html_and_inventories_metadata(self):
        page_a = b"""<!doctype html><html><head><title>Home page</title>
          <script src='/static/app.js?bundle=private'></script></head><body>
          <a href='/about?tracking=hidden'>About</a><a href='/about#section'>Again</a>
          <form action='/submit?key=hidden' method='post'>
            <input name='email' type='email' value='never-return-this'>
            <input name='csrf' value='csrf-secret'>
          </form></body></html>"""
        page_b = b"<html><title>About</title><body>private body text</body></html>"
        server, base = self.make_server(
            {"/": (200, {"Content-Type": "text/html; charset=utf-8"}, page_a),
             "/about": (200, {"Content-Type": "text/html"}, page_b)}
        )
        start = base + "/"
        child = base + "/about"

        result = crawl_site(start, scope=self.allow(start, child))

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["executed"])
        self.assertEqual(result["request_count"], 2)
        self.assertEqual(server.requests, ["/", "/about"])
        first = result["pages"][0]
        self.assertEqual(first["title"], "Home page")
        self.assertEqual(first["links"], [child])
        self.assertEqual(first["scripts"], [base + "/static/app.js"])
        self.assertEqual(first["forms"][0]["action"], base + "/submit")
        self.assertEqual(first["forms"][0]["method"], "POST")
        self.assertEqual(first["forms"][0]["inputs"], [
            {"name": "email", "type": "email"},
            {"name": "csrf", "type": "text"},
        ])
        self.assertIn("no forms submitted", result["note"])

    def test_only_in_scope_links_are_requested_even_across_origins(self):
        cross_server, cross_base = self.make_server(
            {"/foreign": (200, {"Content-Type": "text/html"}, b"<title>Foreign</title>")}
        )
        root_html = (
            f"<a href='/allowed?secret=query-value'>ok</a>"
            f"<a href='/outside'>out of scope</a>"
            f"<a href='{cross_base}/foreign?token=private'>cross origin</a>"
        ).encode()
        local_server, base = self.make_server(
            {"/": (200, {"Content-Type": "text/html"}, root_html),
             "/allowed": (200, {"Content-Type": "text/html"}, b"<title>Allowed</title>"),
             "/outside": (200, {"Content-Type": "text/html"}, b"not expected")}
        )
        start, allowed = base + "/", base + "/allowed"
        result = crawl_site(
            start,
            scope=self.allow(start, allowed, cross_base + "/foreign"),
        )

        self.assertEqual(result["request_count"], 3)
        self.assertEqual(local_server.requests, ["/", "/allowed"])
        self.assertEqual(cross_server.requests, ["/foreign"])
        self.assertNotIn("/outside", local_server.requests)
        self.assertTrue(all("?" not in page["url"] for page in result["pages"]))

    def test_default_crawl_follows_all_in_scope_pages_and_optional_limit_works(self):
        routes = {}
        server, base = self.make_server(routes)
        urls = [base + "/"] + [base + f"/p{i}" for i in range(1, 8)]
        for index, path in enumerate(["/"] + [f"/p{i}" for i in range(1, 8)]):
            next_link = f"<a href='/p{index + 1}'>next</a>" if index < 7 else ""
            routes[path] = (200, {"Content-Type": "text/html"}, next_link.encode())

        invalid = crawl_site(urls[0], scope=self.allow(*urls), max_pages=0)
        self.assertEqual(invalid["status"], "invalid")
        self.assertFalse(invalid["executed"])
        self.assertEqual(server.requests, [])

        result = crawl_site(urls[0], scope=self.allow(*urls))
        expected_paths = ["/"] + [f"/p{i}" for i in range(1, 8)]
        self.assertEqual(result["request_count"], 8)
        self.assertEqual(len(result["pages"]), 8)
        self.assertEqual(server.requests, expected_paths)

        server.requests.clear()
        limited = crawl_site(urls[0], scope=self.allow(*urls), max_pages=6)
        self.assertEqual(limited["request_count"], 6)
        self.assertEqual(server.requests, expected_paths[:6])

    def test_inventory_does_not_truncate_links_scripts_forms_or_fields_by_count(self):
        links = "".join(f"<a href='/path{i}'>link</a>" for i in range(60))
        scripts = "".join(f"<script src='/asset{i}.js'></script>" for i in range(60))
        forms = "".join(
            "<form action='/submit'>"
            + "".join(f"<input name='field{i}'>" for i in range(35))
            + "</form>"
            for _ in range(22)
        )
        html = f"<html>{links}{scripts}{forms}</html>".encode()
        server, base = self.make_server({"/": (200, {"Content-Type": "text/html"}, html)})
        start = base + "/"

        result = crawl_site(start, scope=self.allow(start))
        page = result["pages"][0]

        self.assertEqual(len(page["links"]), 60)
        self.assertEqual(len(page["scripts"]), 60)
        self.assertEqual(len(page["forms"]), 22)
        self.assertEqual(len(page["forms"][0]["inputs"]), 35)
        self.assertEqual(server.requests, ["/"])

    def test_redirect_is_reported_but_not_followed(self):
        server, base = self.make_server(
            {"/redirect": (302, {"Location": "/sink"}, b""),
             "/sink": (200, {"Content-Type": "text/html"}, b"<title>sink</title>")}
        )
        redirect = base + "/redirect"
        result = crawl_site(redirect, scope=self.allow(redirect, base + "/sink"))

        self.assertEqual(result["request_count"], 1)
        self.assertEqual(result["pages"][0]["status_code"], 302)
        self.assertEqual(server.requests, ["/redirect"])

    def test_query_values_form_values_and_raw_body_are_never_returned(self):
        html = b"""<html><title>Safe title</title><body>BODY_SENTINEL_776
          <a href='/next?access_token=query-secret-value'>next</a>
          <script src='/app.js?key=script-query-secret'></script>
          <form action='/login?session=form-query-secret'>
            <input name='password' type='password' value='form-value-secret'>
          </form></body></html>"""
        server, base = self.make_server({"/": (200, {"Content-Type": "text/html"}, html)})
        start = base + "/?start_token=start-query-secret"
        result = crawl_site(start, scope=self.allow(start, base + "/"))
        serialized = json.dumps(result)

        self.assertEqual(server.requests, ["/"])
        self.assertEqual(result["pages"][0]["url"], base + "/")
        self.assertEqual(result["pages"][0]["links"], [base + "/next"])
        for secret in (
            "start-query-secret", "query-secret-value", "script-query-secret",
            "form-query-secret", "form-value-secret", "BODY_SENTINEL_776",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("?", json.dumps(result["pages"][0]["links"]))
        self.assertEqual(result["pages"][0]["forms"][0]["inputs"], [
            {"name": "password", "type": "password"}
        ])

    def test_response_body_read_is_capped(self):
        large = b"<html><title>Large</title>" + (b"x" * (300 * 1024))
        server, base = self.make_server({"/": (200, {"Content-Type": "text/html"}, large)})
        result = crawl_site(base + "/", scope=self.allow(base + "/"))

        page = result["pages"][0]
        self.assertEqual(page["bytes"], 256 * 1024)
        self.assertTrue(page["truncated"])
        self.assertNotIn("x" * 100, json.dumps(result))
        self.assertEqual(server.requests, ["/"])


if __name__ == "__main__":
    unittest.main()
