from __future__ import annotations

import json
import threading
import unittest
from unittest.mock import patch

from labs.local_web_lab import server as lab_server
from labs.local_web_lab.evaluation import evaluate_local_saas_chain
from tools import execute_tool


class LocalLabEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.server = lab_server.LocalLabServer(0)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def _stop_server(self):
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.assertFalse(self.thread.is_alive(), "local lab evaluation server thread did not stop")

    def test_evaluation_builds_confirmed_chain_and_never_returns_fake_bearer(self):
        result = evaluate_local_saas_chain(self.base_url)
        rendered = json.dumps(result, ensure_ascii=False, sort_keys=True)

        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["synthetic_data_only"])
        self.assertEqual(result["scope"], "http://127.0.0.1 only")
        self.assertEqual(result["request_count"], 5)
        self.assertEqual(result["matrix"]["chain_count"], 1)
        self.assertEqual(result["matrix"]["confirmed_chain_count"], 1)
        chain = result["matrix"]["chains"][0]
        self.assertEqual(chain["status"], "confirmed")
        self.assertEqual(chain["finding_ids"], ["LAB-F1", "LAB-F2"])
        self.assertEqual(result["matrix"]["attack_chain_matrix"][1]["depends_on"], ["LAB-F1"])
        self.assertNotIn(lab_server._FAKE_INTEGRATION_BEARER, rendered)
        self.assertNotIn("bearer_token", rendered)

    def test_evaluator_rejects_every_non_loopback_or_non_origin_url_before_connecting(self):
        invalid_urls = [
            "https://127.0.0.1:8765",
            "http://localhost:8765",
            "http://127.0.0.2:8765",
            "http://192.0.2.1:8765",
            "http://[::1]:8765",
            "http://user@127.0.0.1:8765",
            "http://127.0.0.1:8765/path",
            "http://127.0.0.1:8765/?token=fake",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
        ]
        with patch("labs.local_web_lab.evaluation.http.client.HTTPConnection") as connection:
            for invalid_url in invalid_urls:
                with self.subTest(url=invalid_url):
                    result = evaluate_local_saas_chain(invalid_url)
                    self.assertEqual(result["status"], "blocked")
                    self.assertFalse(result["executed"])
            connection.assert_not_called()

    def test_tool_dispatch_calls_only_the_loopback_evaluator(self):
        result = json.loads(execute_tool("evaluate_local_lab_chain", {"base_url": self.base_url}))
        self.assertEqual(result["status"], "completed")
        self.assertNotIn(lab_server._FAKE_INTEGRATION_BEARER, json.dumps(result))

    def test_tool_dispatch_rejects_unexpected_arguments(self):
        result = json.loads(execute_tool("evaluate_local_lab_chain", {"base_url": self.base_url, "token": "no"}))
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
