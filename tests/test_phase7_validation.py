"""
InternGuard AI - Phase 7 Comprehensive Validation & Regression Test Suite
Validates all major scenarios:
A. Normal internship posting (clean, valid-looking, low risk).
B. Suspicious internship (advance fees, unrealistic pay, urgency, Telegram/wire).
C. Missing information (neutral unverified items, not proof of fraud).
D. Invalid inputs (empty, malformed, non-string, 100k length, SSRF/dangerous URLs).
E. Agent behavior (unconfigured, error resilience, mocked investigation, no fabricated evidence).
F. Scoring & caps (evidence deduplication, 45pt/75pt caps, neutrality of technical signals).
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as flask_module
from core.report_generator import ReportGenerator


class TestPhase7ComprehensiveValidation(unittest.TestCase):
    """End-to-end validation across all Phase 7 test requirements."""

    @classmethod
    def setUpClass(cls):
        flask_module.app.testing = True
        cls.client = flask_module.app.test_client()

    # ── Scenario A: Normal internship posting ────────────────────────────────
    def test_scenario_A_normal_internship_posting(self):
        """Plausible internship with company, corporate email and website."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Data Science & ML Research Intern",
                "location": "New York, NY (Hybrid)",
                "description": "Collaborate with senior data scientists on statistical modeling and NLP pipelines. Conduct experiments and document findings.",
                "requirements": "Pursuing Master's or Bachelor's in CS/Statistics. Python, Pandas, Scikit-learn proficiency. Solid foundation in linear algebra.",
                "company_name": "Cognitive Scale AI",
                "contact_email": "careers@cognitivescale.com",
                "company_url": "https://www.cognitivescale.com",
                "stipend": "$4,200 / month"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # Verify report generated without error
            self.assertIn("report", data)
            report = data["report"]
            self.assertIsInstance(report["risk_score"], int)
            self.assertLessEqual(report["risk_score"], 29, f"Expected Low Risk <= 29, got {report['risk_score']}")
            self.assertEqual(report["risk_level"], "LIKELY LEGITIMATE")
            self.assertEqual(data["verdict"], "LEGITIMATE")
            self.assertEqual(data["risk"], "LOW")
            self.assertFalse(data["is_fake"])
            self.assertEqual(data["agent_status"], "unconfigured")
            self.assertEqual(data["tools_executed"], [])

    # ── Scenario B: Suspicious internship ────────────────────────────────────
    def test_scenario_B_suspicious_internship_posting(self):
        """Mandatory registration fee, unrealistic stipend, urgent selection, telegram/wire."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Work from Home Data Entry Intern — Earn $5,000/week Guaranteed!",
                "location": "Remote / Online",
                "description": (
                    "Earn money fast with guaranteed income of $5,000 per week! Immediate selection, no experience required. "
                    "Must be 18. Send money via wire transfer or western union for starter kit. Contact hiring manager exclusively on Telegram. "
                    "Click here to apply now before spots fill up!"
                ),
                "requirements": "Must be 18. Pay $150 registration fee and background check fee.",
                "company_name": "FastCash Global",
                "contact_email": "fastcash-hiring@gmail.com",
                "stipend": "$5,000 / week (Registration fee applies)"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            self.assertIn("report", data)
            report = data["report"]
            self.assertGreaterEqual(report["risk_score"], 70, f"Expected High Risk >= 70, got {report['risk_score']}")
            self.assertEqual(report["risk_level"], "HIGH RISK")
            self.assertEqual(data["verdict"], "FAKE")
            self.assertEqual(data["risk"], "HIGH")
            self.assertTrue(data["is_fake"])

            # Verify accurate reporting of suspicious indicators
            indicators = [item["indicator"] for item in report["score_breakdown"]["risk_indicators"]]
            self.assertIn("advance_fee_demand", indicators)
            self.assertIn("suspicious_payment_channel", indicators)
            self.assertIn("easy_selection", indicators)
            self.assertIn("unverified_chat_channel", indicators)

    # ── Scenario C: Missing information ──────────────────────────────────────
    def test_scenario_C_missing_information_reported_as_unverified(self):
        """Missing optional email, website, stipend, requirements must NOT be treated as fraud."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Junior Python Developer Intern",
                "description": "We are seeking a junior python intern to assist with unit testing and codebase refactoring."
                # contact_email, company_url, stipend, requirements omitted
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            report = data["report"]
            # Missing fields must be noted in unverified_items
            unverified_text = " ".join(report["unverified_items"]).lower()
            self.assertIn("email", unverified_text)
            self.assertIn("website", unverified_text)
            self.assertIn("stipend", unverified_text)

            # Missing information alone must NOT drive the posting into High Risk fraud
            self.assertLessEqual(report["risk_score"], 40)
            self.assertNotEqual(report["risk_level"], "HIGH RISK")

    # ── Scenario D: Invalid inputs ───────────────────────────────────────────
    def test_scenario_D_empty_request_rejected(self):
        """Empty request rejected with HTTP 400."""
        res = self.client.post("/predict", json={})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json())

    def test_scenario_D_malformed_json_rejected(self):
        """Malformed JSON content rejected with HTTP 400."""
        res = self.client.post("/predict", data="{not a valid json", content_type="application/json")
        self.assertEqual(res.status_code, 400)

        res2 = self.client.post("/predict", data="plain text data", content_type="text/plain")
        self.assertEqual(res2.status_code, 400)

    def test_scenario_D_incorrect_data_types_rejected(self):
        """Non-string field types rejected with HTTP 400."""
        # title is integer
        res1 = self.client.post("/predict", json={"title": 12345, "description": "Valid description"})
        self.assertEqual(res1.status_code, 400)
        self.assertIn("Expected a string", res1.get_json()["error"])

        # stipend is list
        res2 = self.client.post("/predict", json={"title": "Intern", "description": "Valid", "stipend": ["500", "month"]})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Expected a string", res2.get_json()["error"])

    def test_scenario_D_extremely_long_input_handled_safely(self):
        """Oversized inputs (> 20,000 chars) rejected with HTTP 400; within limit passes."""
        # 1. Input exceeding limit (100,000 chars) must be rejected with HTTP 400
        oversized_desc = "Software developer intern responsibilities. " + ("Python code analysis " * 5000)
        res_oversized = self.client.post("/predict", json={"title": "Intern", "description": oversized_desc})
        self.assertEqual(res_oversized.status_code, 400)
        self.assertIn("exceeds maximum permitted length", res_oversized.get_json()["error"])

        # 2. Input within permitted limit (e.g. 5,000 chars) is processed safely without crashing
        with patch.dict(os.environ, {}, clear=True):
            valid_long_desc = "Software developer intern responsibilities. " + ("Python code analysis " * 200)
            payload = {"title": "Engineering Intern", "description": valid_long_desc}
            res_valid = self.client.post("/predict", json=payload)
            self.assertEqual(res_valid.status_code, 200)
            data = res_valid.get_json()
            self.assertIn("report", data)
            self.assertIsInstance(data["report"]["risk_score"], int)

    def test_scenario_D_invalid_and_dangerous_urls_safe(self):
        """Dangerous or malformed URLs handled safely without crashing."""
        with patch.dict(os.environ, {}, clear=True):
            dangerous_urls = [
                "javascript:alert(1)",
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data",
                "ftp://malicious.com/file",
                "https://[invalid-ipv6"
            ]
            for url in dangerous_urls:
                payload = {
                    "title": "Software Intern",
                    "description": "Standard software intern duties and testing.",
                    "company_url": url
                }
                res = self.client.post("/predict", json=payload)
                self.assertEqual(res.status_code, 200, f"Failed on URL: {url}")
                data = res.get_json()
                self.assertIn("report", data)

    # ── Scenario E: Agent behavior ───────────────────────────────────────────
    def test_scenario_E_groq_api_key_unavailable(self):
        """When GROQ_API_KEY is unset, agent degrades gracefully without fabricated evidence."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Marketing Intern",
                "description": "Social media content creation and analytics reporting."
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["agent_status"], "unconfigured")
            self.assertEqual(data["tools_executed"], [])
            self.assertIn("Groq API key not configured", " ".join(data["report"]["limitations"]))

    def test_scenario_E_agent_execution_error_resilience(self):
        """When agent encounters runtime error, Flask does not crash and records error status."""
        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_agent.investigate.side_effect = RuntimeError("Groq API rate limit exceeded")

        with patch.object(flask_module.app, "agent", mock_agent):
            payload = {"title": "DevOps Intern", "description": "CI/CD automation pipelines."}
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["agent_status"], "error")
            self.assertEqual(data["tools_executed"], [])
            self.assertIn("report", data)

    def test_scenario_E_agent_successfully_completes_investigation(self):
        """Agent successfully completing investigation has tools recorded and synthesized."""
        mock_agent_result = {
            "status": "completed",
            "agent_summary": "Forensic investigation revealed payment demand and unverified recruiter domain.",
            "tools_selected": ["verify_payment_requests", "verify_company_website"],
            "tool_results": [
                {
                    "tool": "payment_verification",
                    "status": "completed",
                    "is_suspicious": True,
                    "findings": [
                        {
                            "category": "registration_fee",
                            "severity": "CRITICAL",
                            "message": "Mandatory registration fee of $200 required."
                        }
                    ],
                    "evidence": ["Mandatory registration fee of $200 required."],
                    "details": {},
                    "limitations": []
                },
                {
                    "tool": "website_verification",
                    "status": "completed",
                    "is_suspicious": False,
                    "findings": [
                        {
                            "category": "valid_website",
                            "severity": "INFO",
                            "message": "Website reachable (HTTP 200)."
                        }
                    ],
                    "evidence": ["Website reachable."],
                    "details": {"is_reachable": True, "http_status": 200},
                    "limitations": []
                }
            ],
            "investigation_steps": [
                {"round": 1, "action": "called verify_payment_requests"},
                {"round": 2, "action": "called verify_company_website"}
            ],
            "observations": ["Registration fee requested."],
            "unverified_items": [],
            "limitations": [],
            "error": None
        }

        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_agent.investigate.return_value = mock_agent_result

        with patch.object(flask_module.app, "agent", mock_agent):
            payload = {
                "title": "Finance Intern",
                "description": "Financial modeling. Pay $200 registration fee to begin.",
                "company_url": "https://finance-interns.org"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["agent_status"], "completed")
            self.assertEqual(data["tools_executed"], ["verify_payment_requests", "verify_company_website"])
            self.assertIn("advance_fee_demand", [i["indicator"] for i in data["report"]["score_breakdown"]["risk_indicators"]])

    # ── Scenario F: Scoring, Deduplication & Caps ────────────────────────────
    def test_scenario_F_scoring_evidence_caps_and_deduplication(self):
        """Financial exploitation capped at 45, combined evidence capped at 75."""
        canonical_hits = {
            "advance_fee_demand": {
                "category": "advance_fee_demand",
                "raw_points": 35.0,
                "sources": ["Rule Screener", "Payment Verifier"],
                "description": "Mandatory registration fee demanded."
            },
            "suspicious_payment_channel": {
                "category": "suspicious_payment_channel",
                "raw_points": 25.0,
                "sources": ["Rule Screener", "Payment Verifier"],
                "description": "Wire transfer requested."
            },
            "disposable_email_domain": {
                "category": "disposable_email_domain",
                "raw_points": 25.0,
                "sources": ["Email Verifier"],
                "description": "Disposable email."
            },
            "unrealistic_earnings": {
                "category": "unrealistic_earnings",
                "raw_points": 15.0,
                "sources": ["Description Analyzer"],
                "description": "Unrealistic stipend."
            }
        }

        # advance_fee (35) + payment_channel (25 capped to 10) = 45.0
        # + disposable_email (25) + unrealistic_earnings (15) = 85.0 uncapped
        # Combined evidence capped at 75.0
        evidence_score, breakdown, final_score = ReportGenerator._compute_scores_and_breakdown(
            ml_score=25.0,
            fake_prob=83.3,
            canonical_hits=canonical_hits
        )

        self.assertEqual(evidence_score, 75.0, f"Expected evidence score capped at 75.0, got {evidence_score}")
        self.assertTrue(breakdown["evidence_summary"]["evidence_cap_applied"])
        self.assertTrue(breakdown["evidence_summary"]["financial_exploitation_capped"])
        self.assertEqual(breakdown["evidence_summary"]["uncapped_evidence_total"], 85.0)
        self.assertEqual(breakdown["evidence_summary"]["final_evidence_contribution"], 75.0)

        # 25.0 (ML) + 75.0 (Capped Evidence) = 100.0
        self.assertEqual(final_score, 100)

    def test_scenario_F_technical_signals_award_zero_negative_points(self):
        """HTTP 200 reachability and valid MX records award 0.0 negative mitigation points."""
        report = ReportGenerator.generate_report(
            ml_result={"fake_prob": 20.0, "legit_prob": 80.0, "is_fake": False, "verdict": "LEGITIMATE"},
            rule_findings=[],
            agent_result={
                "status": "completed",
                "tools_selected": ["verify_company_website", "verify_email"],
                "tool_results": [
                    {
                        "tool": "verify_company_website",
                        "output": {
                            "findings": [{"category": "valid_website", "message": "HTTP 200 confirmed"}],
                            "details": {"is_reachable": True, "http_status": 200}
                        }
                    },
                    {
                        "tool": "verify_email",
                        "output": {
                            "findings": [{"category": "corporate_email", "message": "MX records valid"}],
                            "details": {"has_mx_records": True}
                        }
                    }
                ]
            },
            posting_details={"title": "Analyst Intern", "description": "Good description."}
        )

        # Mitigation adjustments must be strictly empty
        self.assertEqual(len(report["score_breakdown"]["mitigation_adjustments"]), 0)
        # ML score is 20.0 * 0.3 = 6.0
        self.assertEqual(report["risk_score"], 6)
        # Verified indicators should note technical reachability without claiming verified company
        verified_text = " ".join(report["verified_indicators"]).lower()
        self.assertIn("technical signal observed", verified_text)
        self.assertIn("not confirm legal company legitimacy", verified_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
