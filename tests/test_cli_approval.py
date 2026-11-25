import unittest

from session_authorization import SessionAuthorization


class SessionAuthorizationTests(unittest.TestCase):
    def make_authorizer(self, scope=None, *, budget=None, answer="y"):
        output = []
        authorizer = SessionAuthorization(
            scope if scope is not None else {"allowed_domains": ["example.test"]},
            budget=budget,
            input_fn=lambda prompt: answer,
            output_fn=lambda *parts: output.append(" ".join(str(part) for part in parts)),
        )
        return authorizer, output

    def test_consent_is_requested_once_for_a_visible_scope(self):
        scope = {
            "allowed_domains": ["example.test", "api.example.test"],
            "allowed_urls": ["https://example.test:8443/check?token=do-not-show#fragment"],
        }
        authorizer, output = self.make_authorizer(scope, answer="y")

        self.assertTrue(authorizer.authorize_session())
        self.assertTrue(authorizer("crawl_site", {"url": "https://example.test/", "max_pages": 3}))
        self.assertTrue(authorizer("inspect_page", {"url": "https://example.test/login"}))
        self.assertIsNone(authorizer.remaining)

        shown = "\n".join(output)
        self.assertIn("example.test", shown)
        self.assertIn("https://example.test:8443/check", shown)
        self.assertNotIn("do-not-show", shown)
        self.assertNotIn("token=", shown)
        self.assertIn("غير محدود طلب HTTP", shown)

    def test_declined_session_blocks_remote_requests(self):
        authorizer, _ = self.make_authorizer(answer="n")
        self.assertFalse(authorizer.authorize_session())
        self.assertFalse(authorizer("inspect_page", {"url": "https://example.test/"}))
        self.assertIsNone(authorizer.remaining)

    def test_empty_scope_does_not_prompt_and_stays_disabled(self):
        authorizer = SessionAuthorization(
            {"allowed_domains": [], "allowed_urls": []},
            input_fn=lambda _: self.fail("must not prompt without a scope"),
            output_fn=lambda *_: None,
        )
        self.assertFalse(authorizer.authorize_session())
        self.assertFalse(authorizer("crawl_site", {"url": "https://example.test/"}))

    def test_default_session_has_no_cumulative_request_limit(self):
        authorizer, _ = self.make_authorizer()
        self.assertTrue(authorizer.authorize_session())
        for _ in range(1_000):
            self.assertTrue(authorizer("inspect_page", {"url": "https://example.test/"}))
        self.assertIsNone(authorizer.remaining)

    def test_optional_cumulative_budget_stops_calls_before_the_tool_runs(self):
        authorizer, _ = self.make_authorizer(budget=5)
        self.assertTrue(authorizer.authorize_session())
        self.assertTrue(authorizer("crawl_site", {"url": "https://example.test/", "max_pages": 5}))
        self.assertEqual(authorizer.remaining, 0)
        self.assertFalse(authorizer("inspect_page", {"url": "https://example.test/"}))
        self.assertEqual(authorizer.remaining, 0)

    def test_post_mutations_reserve_their_maximum_request_count(self):
        authorizer, _ = self.make_authorizer(budget=4)
        self.assertTrue(authorizer.authorize_session())
        arguments = {
            "method": "POST",
            "payload_json": '{"id": 1, "role": "viewer", "tenant": "a"}',
        }
        self.assertTrue(authorizer("mutate_and_fuzz_request", arguments))
        self.assertEqual(authorizer.remaining, 0)
        self.assertFalse(authorizer("inspect_page", {"url": "https://example.test/"}))

    def test_local_and_offline_tools_do_not_consume_http_budget(self):
        authorizer, _ = self.make_authorizer(scope={})
        self.assertTrue(authorizer("analyze_javascript", {"source": "const x=1"}))
        self.assertTrue(authorizer("build_attack_chain_matrix", {"findings_json": "[]"}))
        self.assertTrue(authorizer("evaluate_local_lab_chain", {"base_url": "http://127.0.0.1:8765"}))
        self.assertIsNone(authorizer.remaining)


if __name__ == "__main__":
    unittest.main()
