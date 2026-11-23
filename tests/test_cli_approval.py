import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from main import approve_tool_call


class ApprovalDisplayTests(unittest.TestCase):
    def test_http_approval_redacts_secret_like_json_fields(self):
        marker = "REDACTION_TEST_MARKER_001"
        arguments = {
            "url": "http://127.0.0.1:8080/echo",
            "method": "POST",
            "payload_json": json.dumps(
                {"password": marker, "role": "viewer"}
            ),
        }
        output = io.StringIO()
        with patch("builtins.input", return_value="n"), redirect_stdout(output):
            approved = approve_tool_call("mutate_and_fuzz_request", arguments)

        self.assertFalse(approved)
        self.assertNotIn(marker, output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())
        self.assertIn("حتى 4 طلبات HTTP", output.getvalue())

    def test_javascript_approval_never_prints_source(self):
        source_marker = "SYNTHETIC_SOURCE_SHOULD_NOT_APPEAR"
        output = io.StringIO()
        with patch("builtins.input", return_value="n"), redirect_stdout(output):
            approved = approve_tool_call("analyze_javascript", {"source": source_marker})

        self.assertFalse(approved)
        self.assertNotIn(source_marker, output.getvalue())
        self.assertIn("تحليل محلي للنص فقط", output.getvalue())


if __name__ == "__main__":
    unittest.main()
