"""
InternGuard AI - Phase 6 Backend Integration Verification Suite
Tests the integrated Flask application under both:
1. Groq unconfigured (graceful fallback to ML + Heuristics + Phase 5 Report)
2. Agent mocked as completed (full multi-tool execution telemetry + Phase 5 Report)
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as flask_module


class TestPhase6BackendIntegration(unittest.TestCase):

    def setUp(self):
        self.app = flask_module.app
        self.app.testing = True
        self.client = self.app.test_client()

    def test_01_groq_unconfigured_request(self):
        """Test POST /predict when GROQ_API_KEY is not set."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Machine Learning Research Intern",
                "location": "Boston, MA",
                "description": "Participate in research experiments, evaluate model benchmarks, and draft technical papers.",
                "requirements": "Solid math foundations, linear algebra, and Python proficiency.",
                "company_name": "DeepResearch Labs",
                "contact_email": "recruiter@deepresearchlabs.org",
                "company_url": "https://deepresearchlabs.org",
                "stipend": "$3,000 / month"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # 1. Verify backward-compatible fields
            backward_compat_keys = {"is_fake", "fake_prob", "legit_prob", "confidence", "risk", "verdict", "red_flags"}
            self.assertTrue(backward_compat_keys.issubset(data.keys()))
            self.assertIsInstance(data["is_fake"], bool)
            self.assertIsInstance(data["fake_prob"], float)
            self.assertIsInstance(data["legit_prob"], float)
            self.assertIsInstance(data["risk"], str)
            self.assertIsInstance(data["verdict"], str)
            self.assertIsInstance(data["red_flags"], list)

            # 2. Verify new Phase 6 fields
            phase6_keys = {"agent_status", "tools_executed", "report"}
            self.assertTrue(phase6_keys.issubset(data.keys()))
            self.assertEqual(data["agent_status"], "unconfigured")
            self.assertEqual(data["tools_executed"], [])

            # 3. Verify complete Phase 5 report structure
            report = data["report"]
            report_expected_keys = {
                "risk_score",
                "risk_level",
                "verdict",
                "summary",
                "score_breakdown",
                "ml_assessment",
                "rule_based_findings",
                "investigation_findings",
                "security_events",
                "input_validation_events",
                "verified_indicators",
                "suspicious_indicators",
                "unverified_items",
                "limitations",
                "recommendations"
            }
            self.assertTrue(report_expected_keys.issubset(report.keys()))
            self.assertIsInstance(report["risk_score"], int)
            self.assertIn("ml_contribution", report["score_breakdown"])
            self.assertIn("evidence_summary", report["score_breakdown"])
            self.assertEqual(data["verdict"], "LEGITIMATE")
            self.assertEqual(data["risk"], "LOW")
            self.assertFalse(data["is_fake"])

    def test_02_agent_mocked_as_completed(self):
        """Test POST /predict when agent runs and completes multi-tool investigation."""
        mock_agent_result = {
            "status": "completed",
            "agent_summary": "Forensic investigation revealed payment demand and unverified recruiter domain.",
            "tools_selected": ["verify_payment_requests", "verify_email"],
            "tool_results": [
                {
                    "tool": "payment_verification",
                    "status": "completed",
                    "is_suspicious": True,
                    "findings": [
                        {
                            "category": "registration_fee",
                            "severity": "CRITICAL",
                            "message": "Mandatory upfront registration fee of $150 demanded."
                        }
                    ],
                    "evidence": ["Mandatory upfront registration fee of $150 demanded."],
                    "details": {"explicit_demands_count": 1},
                    "limitations": []
                },
                {
                    "tool": "email_verification",
                    "status": "completed",
                    "is_suspicious": False,
                    "findings": [],
                    "evidence": [],
                    "details": {
                        "is_valid_format": True,
                        "has_mx_records": True,
                        "domain": "deepresearchlabs.org"
                    },
                    "limitations": []
                }
            ],
            "investigation_steps": [
                {"round": 1, "action": "called verify_payment_requests"},
                {"round": 2, "action": "called verify_email"}
            ],
            "observations": ["Mandatory upfront registration fee of $150 demanded."],
            "unverified_items": ["Company website URL was not provided in posting."],
            "limitations": ["Live external reachability limited to tested endpoints."],
            "error": None
        }

        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_agent.investigate.return_value = mock_agent_result

        with patch.object(self.app, "agent", mock_agent):
            payload = {
                "title": "Machine Learning Research Intern",
                "location": "Boston, MA",
                "description": "Participate in research experiments, evaluate model benchmarks. Pay $150 registration fee to begin.",
                "requirements": "Solid math foundations, linear algebra, and Python proficiency.",
                "company_name": "DeepResearch Labs",
                "contact_email": "recruiter@deepresearchlabs.org",
                "stipend": "Pay 150 registration fee"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # Verify backward compatibility
            self.assertIn("is_fake", data)
            self.assertIn("fake_prob", data)
            self.assertIn("legit_prob", data)
            self.assertIn("confidence", data)
            self.assertIn("risk", data)
            self.assertIn("verdict", data)
            self.assertIn("red_flags", data)

            # Verify agent telemetry
            self.assertEqual(data["agent_status"], "completed")
            self.assertEqual(data["tools_executed"], ["verify_payment_requests", "verify_email"])

            # Verify report synthesized the fee finding
            report = data["report"]
            indicators = [item["indicator"] for item in report["score_breakdown"]["risk_indicators"]]
            self.assertIn("advance_fee_demand", indicators)
            self.assertGreaterEqual(report["risk_score"], 35)

    def test_03_agent_exception_handled_gracefully(self):
        """Test that if the agent raises an unhandled exception, Flask does not crash."""
        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_agent.investigate.side_effect = RuntimeError("Groq API connection timeout")

        with patch.object(self.app, "agent", mock_agent):
            payload = {
                "title": "Software Engineering Intern",
                "description": "Backend API development with Python and Django."
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            self.assertEqual(data["agent_status"], "error")
            self.assertEqual(data["tools_executed"], [])
            self.assertIn("report", data)
            self.assertIn("risk_score", data["report"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
