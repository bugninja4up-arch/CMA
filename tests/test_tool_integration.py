import json
import unittest
from unittest.mock import patch

from agent import Agent
from tools import TOOL_SCHEMAS, execute_tool


class FakeDatabase:
    def recent_context(self):
        return ""

    def add_interaction(self, request, response):
        pass


class ToolIntegrationTests(unittest.TestCase):
    def make_agent(self, scope, approved=True):
        approvals = []

        def approval(name, arguments):
            approvals.append((name, arguments))
            return approved

        return Agent(
            provider=None,
            db_manager=FakeDatabase(),
            scope=scope,
            approval_callback=approval,
        ), approvals

    def test_new_tool_schemas_are_exposed(self):
        names = {schema["function"]["name"] for schema in TOOL_SCHEMAS}
        self.assertIn("crawl_site", names)
        self.assertIn("inspect_page", names)

    def test_crawl_requires_approval_then_dispatches_with_configured_scope(self):
        url = "https://example.test/"
        scope = {"allowed_domains": ["example.test"]}
        agent, approvals = self.make_agent(scope)
        with patch("tools.crawl_site", return_value={"status": "completed", "executed": True}) as crawl:
            result = json.loads(agent._dispatch_tool("crawl_site", json.dumps({"url": url, "max_pages": 2})))

        self.assertEqual(result["status"], "completed")
        self.assertEqual([name for name, _ in approvals], ["crawl_site"])
        crawl.assert_called_once_with(url, scope=scope, max_pages=2)

    def test_inspection_requires_approval_and_out_of_scope_is_blocked_before_it(self):
        url = "https://example.test/page?token=synthetic"
        scope = {"allowed_domains": ["example.test"]}
        agent, approvals = self.make_agent(scope, approved=False)
        not_approved = json.loads(agent._dispatch_tool("inspect_page", json.dumps({"url": url})))
        self.assertEqual(not_approved["status"], "not_approved")
        self.assertEqual([name for name, _ in approvals], ["inspect_page"])

        outside, outside_approvals = self.make_agent({"allowed_domains": []})
        with patch("tools.inspect_page") as inspect:
            blocked = json.loads(outside._dispatch_tool("inspect_page", json.dumps({"url": url})))
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(outside_approvals, [])
        inspect.assert_not_called()

    def test_direct_dispatch_for_new_active_tools_fails_closed_without_scope(self):
        crawl = json.loads(execute_tool("crawl_site", {"url": "https://example.test/"}))
        inspect = json.loads(execute_tool("inspect_page", {"url": "https://example.test/"}))
        self.assertEqual(crawl["status"], "blocked")
        self.assertFalse(crawl["executed"])
        self.assertEqual(inspect["status"], "blocked")
        self.assertFalse(inspect["executed"])


if __name__ == "__main__":
    unittest.main()
