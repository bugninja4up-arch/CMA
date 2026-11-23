import json
import threading
import unittest
from types import SimpleNamespace
from urllib.request import ProxyHandler, Request, build_opener

from agent import Agent
from lab.app import create_lab_server


class FakeDatabase:
    def __init__(self):
        self.saved = []

    def recent_context(self):
        return ""

    def add_interaction(self, request, response):
        self.saved.append((request, response))


class ScriptedCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=json.dumps(arguments))


class ScriptedMessage:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

    def model_dump(self, exclude_none=True):
        value = {"role": "assistant"}
        if self.content is not None or not exclude_none:
            value["content"] = self.content
        if self.tool_calls is not None or not exclude_none:
            value["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
                for call in (self.tool_calls or [])
            ]
        return value


class ScriptedProvider:
    """Deterministic local model stand-in; it never calls an external provider."""

    def __init__(self, plan):
        self.plan = list(plan)
        self.index = 0
        self.results = []
        self._seen = set()

    def complete(self, messages):
        for message in messages:
            if message.get("role") == "tool" and message.get("tool_call_id") not in self._seen:
                self._seen.add(message.get("tool_call_id"))
                self.results.append(json.loads(message["content"]))
        if self.index < len(self.plan):
            name, arguments = self.plan[self.index]
            call = ScriptedCall(f"lab-call-{self.index + 1}", name, arguments)
            self.index += 1
            assistant = ScriptedMessage(tool_calls=[call])
        else:
            assistant = ScriptedMessage(
                content="انتهى اختبار المختبر المحلي؛ الأثر الاصطناعي والضوابط السلبية موثقة في نتيجة التشغيل."
            )
        return SimpleNamespace(choices=[SimpleNamespace(message=assistant)])


class CMASyntheticLabTests(unittest.TestCase):
    def setUp(self):
        self.server = create_lab_server(0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _fetch_frontend(self):
        opener = build_opener(ProxyHandler({}))
        with opener.open(self.base_url + "/static/app.js", timeout=2) as response:
            self.assertEqual(response.headers.get("X-CMA-Lab"), "synthetic-v1")
            return response.read().decode("utf-8")

    def _request_args(self, url, method, payload, actor=None):
        result = {
            "url": url,
            "method": method,
            "payload_json": json.dumps(payload),
            "baseline_only": True,
        }
        if actor is not None:
            result["lab_actor"] = actor
        return result

    def test_cma_customer_flow_reproduces_role_escalation_chain_and_controls(self):
        frontend = self._fetch_frontend()
        accept_url = self.base_url + "/api/v1/invitations/accept"
        aurora_export = self.base_url + "/api/v1/tenants/aurora/billing/export"
        northstar_accept = accept_url
        northstar_export = self.base_url + "/api/v1/tenants/northstar/billing/export"
        allowed = [accept_url, aurora_export, northstar_export]
        approvals = []

        plan = [
            ("analyze_javascript", {"source": frontend}),
            ("mutate_and_fuzz_request", self._request_args(
                accept_url, "POST",
                {"invite_code": "SYNTHETIC-AURORA-CONTROL-001", "role": "viewer"},
                "viewer",
            )),
            ("mutate_and_fuzz_request", self._request_args(aurora_export, "GET", {}, "viewer")),
            ("mutate_and_fuzz_request", self._request_args(
                accept_url, "POST",
                {"invite_code": "SYNTHETIC-AURORA-ATTACK-001", "role": "billing_admin"},
                "attacker",
            )),
            ("mutate_and_fuzz_request", self._request_args(aurora_export, "GET", {}, "attacker")),
            ("mutate_and_fuzz_request", self._request_args(
                northstar_accept, "POST",
                {"invite_code": "SYNTHETIC-NORTHSTAR-CONTROL-001", "role": "billing_admin"},
                "control",
            )),
            ("mutate_and_fuzz_request", self._request_args(northstar_export, "GET", {}, "control")),
            ("mutate_and_fuzz_request", self._request_args(
                accept_url, "POST",
                {"invite_code": "SYNTHETIC-AURORA-MISMATCH-001", "role": "viewer"},
                "outsider",
            )),
            ("mutate_and_fuzz_request", self._request_args(
                accept_url, "POST",
                {"invite_code": "SYNTHETIC-AURORA-MISMATCH-001", "role": "viewer"},
            )),
        ]
        provider = ScriptedProvider(plan)
        database = FakeDatabase()

        def approve(name, arguments):
            approvals.append((name, arguments))
            return True  # Synthetic loopback lab only; no external target is in scope.

        agent = Agent(
            provider=provider,
            db_manager=database,
            scope={"allowed_urls": allowed},
            approval_callback=approve,
            max_tool_rounds=12,
        )
        final_text = agent.respond("اختبر رحلة العميل داخل اللاب الاصطناعي فقط.")

        self.assertIn("انتهى اختبار المختبر المحلي", final_text)
        self.assertEqual(len(approvals), len(plan))
        self.assertEqual(len(database.saved), 1)
        self.assertEqual(len(provider.results), len(plan))

        analysis = provider.results[0]
        self.assertIn("/api/v1/invitations/accept", analysis["endpoints"])
        self.assertTrue(any(item["kind"] == "invite_code" for item in analysis["potential_secrets"]))
        self.assertNotIn("SYNTHETIC-AURORA-ATTACK-001", json.dumps(analysis))

        results = provider.results[1:]
        self.assertEqual(results[0]["cases"][0]["status_code"], 201)
        self.assertEqual(results[0]["cases"][0]["lab_evidence"], "membership:aurora:viewer")
        self.assertEqual(results[1]["cases"][0]["status_code"], 403)
        self.assertEqual(results[1]["cases"][0]["lab_evidence"], "billing-export:denied")
        self.assertEqual(results[2]["cases"][0]["status_code"], 201)
        self.assertEqual(results[2]["cases"][0]["lab_evidence"], "membership:aurora:billing_admin")
        self.assertEqual(results[3]["cases"][0]["status_code"], 200)
        self.assertEqual(results[3]["cases"][0]["lab_evidence"], "billing-export:authorized:synthetic")
        self.assertEqual(results[4]["cases"][0]["lab_evidence"], "membership:northstar:viewer")
        self.assertEqual(results[5]["cases"][0]["status_code"], 403)
        self.assertEqual(results[6]["cases"][0]["status_code"], 403)
        self.assertEqual(results[6]["cases"][0]["lab_evidence"], "invite:recipient_mismatch")
        self.assertEqual(results[7]["cases"][0]["status_code"], 401)
        self.assertEqual(results[7]["cases"][0]["lab_evidence"], "identity:required")

        # Confirm the unauthorized effect itself, not merely a response status or hash.
        request = Request(
            aurora_export,
            headers={"X-CMA-Lab-Actor": "attacker"},
            method="GET",
        )
        opener = build_opener(ProxyHandler({}))
        with opener.open(request, timeout=2) as response:
            export_body = response.read().decode("utf-8")
        self.assertIn("SYNTHETIC-AURORA-INVOICE-001", export_body)
        self.assertIn("billing@aurora.test", export_body)

    def test_synthetic_actor_is_blocked_before_approval_outside_cma_lab_routes(self):
        urls = [
            "https://example.test/api/v1/invitations/accept",
            self.base_url + "/healthz",
            self.base_url.replace("127.0.0.1", "127.0.0.2") + "/api/v1/invitations/accept",
            self.base_url.replace("http://", "https://") + "/api/v1/invitations/accept",
            self.base_url.replace("127.0.0.1", "[::1]") + "/api/v1/invitations/accept",
        ]
        for url in urls:
            with self.subTest(url=url):
                approvals = []
                agent = Agent(
                    provider=None,
                    db_manager=FakeDatabase(),
                    scope={"allowed_urls": [url]},
                    approval_callback=lambda name, args: approvals.append(name) or True,
                )
                args = self._request_args(
                    url,
                    "POST",
                    {"invite_code": "SYNTHETIC-AURORA-ATTACK-001", "role": "viewer"},
                    "attacker",
                )

                result = json.loads(agent._dispatch_tool("mutate_and_fuzz_request", json.dumps(args)))

                self.assertEqual(result["status"], "blocked")
                self.assertFalse(result["executed"])
                self.assertEqual(approvals, [])


if __name__ == "__main__":
    unittest.main()
