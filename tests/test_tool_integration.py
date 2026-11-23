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
        self.assertIn("build_attack_chain_matrix", names)
        self.assertIn("evaluate_local_lab_chain", names)

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

    def test_chain_matrix_is_offline_and_requires_explicit_human_approval(self):
        finding = {
            "id": "F-1",
            "title": "Local synthetic access control issue",
            "status": "confirmed",
            "evidence": ["HTTP 200 in the owned local lab."],
            "impact": "Synthetic lab record disclosure.",
        }
        agent, approvals = self.make_agent({})

        result = json.loads(agent._dispatch_tool(
            "build_attack_chain_matrix",
            json.dumps({"findings_json": json.dumps([finding])}),
        ))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["chain_count"], 0)
        self.assertEqual([name for name, _ in approvals], ["build_attack_chain_matrix"])

    def test_local_lab_evaluation_requires_approval_and_dispatches_exact_origin(self):
        base_url = "http://127.0.0.1:8765"
        agent, approvals = self.make_agent({})
        with patch("tools.evaluate_local_saas_chain", return_value={"status": "completed", "executed": True}) as evaluate:
            result = json.loads(agent._dispatch_tool("evaluate_local_lab_chain", json.dumps({"base_url": base_url})))

        self.assertEqual(result["status"], "completed")
        self.assertEqual([name for name, _ in approvals], ["evaluate_local_lab_chain"])
        evaluate.assert_called_once_with(base_url)

    def test_local_lab_evaluation_is_not_run_when_approval_is_denied(self):
        agent, approvals = self.make_agent({}, approved=False)
        with patch("tools.evaluate_local_saas_chain") as evaluate:
            result = json.loads(agent._dispatch_tool(
                "evaluate_local_lab_chain",
                json.dumps({"base_url": "http://127.0.0.1:8765"}),
            ))
        self.assertEqual(result["status"], "not_approved")
        self.assertEqual([name for name, _ in approvals], ["evaluate_local_lab_chain"])
        evaluate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
