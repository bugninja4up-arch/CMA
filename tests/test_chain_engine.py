import unittest

from tools.chain_engine import build_attack_chain_matrix


def verification(reproduction=True, impact=True, negative_control=True):
    return {
        "reproduction": {"passed": reproduction, "evidence": [1]},
        "impact": {"passed": impact, "evidence": [2]},
        "negative_control": {"passed": negative_control, "evidence": [3]},
    }


class AttackChainMatrixTests(unittest.TestCase):
    def test_explicit_evidenced_dependencies_make_a_confirmed_chain(self):
        findings = [
            {
                "id": "F-001",
                "title": "Cross-tenant export read",
                "status": "confirmed",
                "summary": "Low-privilege user read another tenant's export.",
                "preconditions": ["A low-privilege account in tenant red."],
                "evidence": [
                    "Positive reproduction: HTTP 200 for the foreign export.",
                    "Impact: response object identifies tenant blue.",
                    "Negative control: same export without a session returns HTTP 401.",
                ],
                "verification": verification(),
                "capability_gain": "Read the foreign export and synthetic integration token.",
                "impact": "Cross-tenant export disclosure.",
                "remediation": ["Enforce object ownership on every export read."],
            },
            {
                "id": "F-002",
                "title": "Service token is not tenant-bound",
                "status": "confirmed",
                "depends_on": ["F-001"],
                "summary": "The token exposed by the export is accepted for another tenant.",
                "preconditions": ["The token obtained in F-001."],
                "evidence": [
                    "Positive reproduction: request using the synthetic token returns HTTP 200.",
                    "Impact: response identifies tenant blue report data.",
                    "Negative control: report request without authorization returns HTTP 401.",
                ],
                "verification": verification(),
                "capability_gain": "Read a synthetic report from tenant blue.",
                "impact": "Cross-tenant report disclosure.",
                "remediation": ["Bind tokens to audience and tenant; re-check ownership."],
            },
            {
                "id": "F-003",
                "title": "Sensitive report content exposed",
                "status": "confirmed",
                "depends_on": ["F-002"],
                "summary": "The downstream response contains synthetic report data.",
                "evidence": [
                    "Positive reproduction: synthetic report marker is present in the response.",
                    "Impact: returned record belongs to a different synthetic tenant.",
                    "Negative control: unauthenticated report request returns HTTP 401.",
                ],
                "verification": verification(),
                "impact": "Exposure of another tenant's report data.",
                "remediation": ["Restrict report reads to the authenticated tenant."],
            },
        ]

        result = build_attack_chain_matrix(findings)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["chain_count"], 1)
        self.assertEqual(result["confirmed_chain_count"], 1)
        self.assertEqual(result["chains"][0]["status"], "confirmed")
        self.assertEqual(result["chains"][0]["finding_ids"], ["F-001", "F-002", "F-003"])
        self.assertEqual([row["step"] for row in result["attack_chain_matrix"]], [1, 2, 3])
        self.assertEqual(result["attack_chain_matrix"][1]["depends_on"], ["F-001"])

    def test_unconfirmed_dependency_never_becomes_a_confirmed_chain(self):
        result = build_attack_chain_matrix([
            {"id": "F-1", "title": "Observed token exposure", "status": "observed", "evidence": ["Synthetic marker in response."]},
            {"id": "F-2", "title": "Potential cross-tenant read", "status": "hypothesis", "depends_on": ["F-1"], "impact": "Possible tenant data exposure."},
        ])

        self.assertEqual(result["chain_count"], 1)
        self.assertEqual(result["confirmed_chain_count"], 0)
        self.assertEqual(result["chains"][0]["status"], "incomplete")
        self.assertEqual(result["chains"][0]["unconfirmed_steps"], ["F-1", "F-2"])

    def test_confirmed_without_evidence_is_downgraded_to_hypothesis(self):
        result = build_attack_chain_matrix([
            {"id": "F-1", "title": "Claimed issue", "status": "confirmed"},
            {"id": "F-2", "title": "Claimed impact", "status": "confirmed", "depends_on": ["F-1"], "evidence": ["A response was observed."], "impact": "Potential record disclosure."},
        ])

        self.assertEqual(result["chains"][0]["status"], "incomplete")
        self.assertEqual(result["chains"][0]["steps"][0]["status"], "hypothesis")
        self.assertIn("no evidence", result["chains"][0]["steps"][0]["status_note"] if "status_note" in result["chains"][0]["steps"][0] else "")
        self.assertEqual(result["chains"][0]["steps"][1]["status"], "observed")
        self.assertIn("negative-control", result["chains"][0]["steps"][1]["status_note"])

    def test_confirmation_requires_passed_reproduction_impact_control_and_references(self):
        failed_control = build_attack_chain_matrix([
            {
                "id": "F-1",
                "title": "Candidate with failed negative control",
                "status": "confirmed",
                "evidence": ["positive result", "impact record", "control result"],
                "verification": verification(negative_control=False),
                "impact": "Synthetic record disclosure.",
            }
        ])
        self.assertEqual(failed_control["standalone_findings"][0]["status"], "observed")
        self.assertIn("negative_control", failed_control["standalone_findings"][0]["status_note"])

        missing_impact = build_attack_chain_matrix([
            {
                "id": "F-4",
                "title": "No concrete impact statement",
                "status": "confirmed",
                "evidence": ["reproduction", "impact output", "control"],
                "verification": verification(),
                "impact": "   ",
            }
        ])
        self.assertEqual(missing_impact["standalone_findings"][0]["status"], "observed")
        self.assertIn("concrete impact", missing_impact["standalone_findings"][0]["status_note"])

        hypothesis = build_attack_chain_matrix([
            {
                "id": "F-5",
                "title": "Still a hypothesis",
                "status": "hypothesis",
                "evidence": ["reproduction", "impact", "control"],
                "verification": verification(),
                "impact": "Potential synthetic record disclosure.",
            }
        ])
        self.assertEqual(hypothesis["standalone_findings"][0]["status"], "hypothesis")

        missing_checklist = build_attack_chain_matrix([
            {
                "id": "F-2",
                "title": "Unstructured claim",
                "status": "confirmed",
                "evidence": ["response observed"],
                "impact": "Synthetic record disclosure.",
            }
        ])
        self.assertEqual(missing_checklist["standalone_findings"][0]["status"], "observed")

        invalid_reference = verification()
        invalid_reference["impact"]["evidence"] = [4]
        invalid = build_attack_chain_matrix([
            {
                "id": "F-3",
                "title": "Out-of-range evidence reference",
                "status": "confirmed",
                "evidence": ["reproduction", "impact", "control"],
                "verification": invalid_reference,
            }
        ])
        self.assertEqual(invalid["status"], "invalid_input")
        self.assertIn("outside the supplied list", invalid["error"])

    def test_findings_without_explicit_dependencies_remain_standalone(self):
        result = build_attack_chain_matrix([
            {"id": "F-1", "title": "Potential issue A", "status": "hypothesis"},
            {"id": "F-2", "title": "Potential issue B", "status": "observed", "evidence": ["Synthetic evidence."]},
        ])

        self.assertEqual(result["chain_count"], 0)
        self.assertEqual(result["attack_chain_matrix"], [])
        self.assertEqual([item["id"] for item in result["standalone_findings"]], ["F-1", "F-2"])

    def test_invalid_dependency_and_cycles_are_rejected(self):
        unknown = build_attack_chain_matrix([
            {"id": "F-1", "title": "A", "status": "confirmed", "evidence": ["proof"], "depends_on": ["MISSING"]}
        ])
        cycle = build_attack_chain_matrix([
            {"id": "F-1", "title": "A", "status": "confirmed", "evidence": ["proof"], "depends_on": ["F-2"]},
            {"id": "F-2", "title": "B", "status": "confirmed", "evidence": ["proof"], "depends_on": ["F-1"]},
        ])

        self.assertEqual(unknown["status"], "invalid_input")
        self.assertIn("unknown dependency", unknown["error"])
        self.assertEqual(cycle["status"], "invalid_input")
        self.assertIn("cycle", cycle["error"])

    def test_secret_like_values_are_redacted_from_evidence_summaries(self):
        result = build_attack_chain_matrix([
            {
                "id": "F-1",
                "title": "Synthetic token found",
                "status": "confirmed",
                "evidence": [
                    "Authorization: Bearer labtok_demo_123456789 apiKey=synthetic_secret_123 invite_code=synthetic_invite_code_123 session_id=synthetic_session_456"
                ],
            }
        ])
        output = str(result)

        self.assertNotIn("labtok_demo_123456789", output)
        self.assertNotIn("synthetic_secret_123", output)
        self.assertNotIn("synthetic_invite_code_123", output)
        self.assertNotIn("synthetic_session_456", output)
        self.assertIn("[REDACTED]", output)


if __name__ == "__main__":
    unittest.main()
