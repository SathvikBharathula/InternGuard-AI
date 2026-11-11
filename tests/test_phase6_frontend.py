"""
InternGuard AI - Phase 6 Frontend Integration Verification Suite
Tests the integration between templates/index.html, static/js/main.js, and app.py.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as flask_module


class TestPhase6FrontendIntegration(unittest.TestCase):

    def setUp(self):
        self.app = flask_module.app
        self.app.testing = True
        self.client = self.app.test_client()

    def test_01_index_html_serves_all_required_dom_elements(self):
        """Verify GET / returns HTTP 200 and renders all dashboard IDs."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        required_ids = [
            "jobForm",
            "btnAnalyze",
            "btnReset",
            "titleInput",
            "locationInput",
            "descriptionInput",
            "requirementsInput",
            "companyInput",
            "emailInput",
            "websiteInput",
            "stipendInput",
            "resultPanel",
            "verdictBanner",
            "verdictIcon",
            "verdictHeading",
            "verdictSub",
            "riskBadge",
            "riskScoreNum",
            "riskScoreBar",
            "agentStatusPill",
            "agentStatusDesc",
            "toolsExecutedList",
            "fakePct",
            "legitPct",
            "probBar",
            "mlScoreContribution",
            "mlModelArchitecture",
            "mlDisclaimer",
            "calcSummaryBox",
            "cappedSummaryRow",
            "scoreIndicatorsList",
            "suspiciousCard",
            "suspiciousList",
            "rulesCard",
            "rulesList",
            "forensicCard",
            "forensicList",
            "verifiedCard",
            "verifiedList",
            "unverifiedCard",
            "unverifiedList",
            "limitationsList",
            "recommendationsSection",
            "recommendationsList",
            "toast",
            "toastMsg"
        ]

        for elem_id in required_ids:
            self.assertIn(f'id="{elem_id}"', html, f"Missing required element ID in index.html: {elem_id}")

    def test_02_static_assets_serve_correctly(self):
        """Verify static CSS and JS are served with HTTP 200."""
        res_css = self.client.get("/static/css/style.css")
        self.assertEqual(res_css.status_code, 200)
        css_text = res_css.get_data(as_text=True)
        self.assertIn(".dashboard-grid", css_text)
        self.assertIn(".score-bar-fill", css_text)
        self.assertIn(".agent-pill", css_text)

        res_js = self.client.get("/static/js/main.js")
        self.assertEqual(res_js.status_code, 200)
        js_text = res_js.get_data(as_text=True)
        self.assertIn("function renderResult", js_text)
        self.assertIn("createEl", js_text)
        self.assertIn("textContent", js_text)

    def test_03_form_submission_unconfigured_groq_response(self):
        """Verify form submission payload against backend with Groq unconfigured."""
        with patch.dict(os.environ, {}, clear=True):
            payload = {
                "title": "Software Engineering Intern — Backend (Python/Django)",
                "location": "US, CA, San Francisco (Hybrid)",
                "description": "We are looking for a passionate software engineering intern to join our platform team.",
                "requirements": "Python, Django, PostgreSQL, and Git familiarity.",
                "company_name": "DataPulse Analytics Inc.",
                "contact_email": "careers@datapulse.io",
                "company_url": "https://www.datapulse.io",
                "stipend": "$4,500 / month"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            # Verify authoritative assessment
            self.assertIn("report", data)
            report = data["report"]
            self.assertEqual(data["agent_status"], "unconfigured")
            self.assertEqual(data["tools_executed"], [])
            self.assertIsInstance(report["risk_score"], int)
            self.assertLessEqual(report["risk_score"], 29)
            self.assertEqual(report["verdict"], "LIKELY LEGITIMATE")
            self.assertEqual(data["verdict"], "LEGITIMATE")
            self.assertEqual(data["risk"], "LOW")
            self.assertFalse(data["is_fake"])
            self.assertIn("ml_assessment", report)
            self.assertIn("score_breakdown", report)
            self.assertIn("verified_indicators", report)
            self.assertIn("recommendations", report)

    def test_04_form_submission_completed_mocked_agent(self):
        """Verify form submission with completed mocked Groq agent."""
        mock_result = {
            "status": "completed",
            "agent_summary": "Forensic investigation revealed advance registration fee demand.",
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
                            "message": "Mandatory registration fee of $100 required."
                        }
                    ],
                    "evidence": ["Mandatory registration fee of $100 required."],
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
                    "evidence": ["Website returned HTTP 200."],
                    "details": {"is_reachable": True, "http_status": 200},
                    "limitations": []
                }
            ],
            "investigation_steps": [
                {"round": 1, "action": "called verify_payment_requests"},
                {"round": 2, "action": "called verify_company_website"}
            ],
            "observations": ["Upfront fee demanded."],
            "unverified_items": [],
            "limitations": [],
            "error": None
        }

        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_agent.investigate.return_value = mock_result

        with patch.object(self.app, "agent", mock_agent):
            payload = {
                "title": "Online Data Clerk Intern",
                "location": "Remote",
                "description": "Simple data entry work. Must pay $100 registration fee to begin.",
                "requirements": "None",
                "company_name": "Apex Tasks",
                "contact_email": "tasks@apex.xyz",
                "company_url": "https://apex.xyz",
                "stipend": "Pay 100 registration fee"
            }
            res = self.client.post("/predict", json=payload)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()

            self.assertEqual(data["agent_status"], "completed")
            self.assertEqual(data["tools_executed"], ["verify_payment_requests", "verify_company_website"])
            report = data["report"]
            self.assertGreaterEqual(report["risk_score"], 35)
            self.assertIn("advance_fee_demand", [i["indicator"] for i in report["score_breakdown"]["risk_indicators"]])
            self.assertIn("verified_indicators", report)

    def test_05_validation_errors(self):
        """Verify client error handling for empty / invalid submissions."""
        # Neither title nor description provided
        res = self.client.post("/predict", json={"location": "Remote"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Empty input", res.get_json()["error"])

        # Non-string data type
        res2 = self.client.post("/predict", json={"title": 9999, "description": "Valid text"})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Expected a string", res2.get_json()["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
