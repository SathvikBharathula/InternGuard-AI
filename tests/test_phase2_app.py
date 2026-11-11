"""
InternGuard AI - Phase 2 Comprehensive Test Suite
Validates application routes, ML inference, rule screener heuristics,
backward compatibility, and payload validation.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as flask_module
from core.ml_predictor import MLPredictor
from core.rule_screener import RuleScreener


class TestInternGuardAIPhase2(unittest.TestCase):
    """Integration and regression test suite for InternGuard AI Phase 2."""

    @classmethod
    def setUpClass(cls):
        flask_module.app.testing = True
        cls.client = flask_module.app.test_client()

    # 1. GET / returns HTTP 200 and loads HTML template
    def test_01_get_home_returns_200(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("InternGuard AI", res.get_data(as_text=True))

    # 2. POST /predict backward compatibility
    def test_02_post_predict_backward_compatibility(self):
        payload = {"title": "Junior Python Developer Intern", "description": "Writing unit tests and bug fixes"}
        res = self.client.post("/predict", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        expected_keys = {"is_fake", "fake_prob", "legit_prob", "confidence", "risk", "red_flags", "verdict"}
        self.assertTrue(expected_keys.issubset(data.keys()))
        self.assertIsInstance(data["is_fake"], bool)
        self.assertIsInstance(data["fake_prob"], float)
        self.assertIsInstance(data["legit_prob"], float)
        self.assertIsInstance(data["red_flags"], list)

    # 3. Legitimate sample posting prediction
    def test_03_legitimate_sample_prediction(self):
        payload = {
            "title": "Software Engineer — Backend (Python/Django)",
            "location": "US, CA, San Francisco",
            "description": "We are looking for a passionate software engineer to join our growing engineering team. You will design and implement scalable REST APIs, collaborate with product managers, and participate in code reviews. We offer a competitive salary, health benefits, and equity.",
            "requirements": "3+ years of experience with Python and Django. Familiarity with PostgreSQL and Redis. Strong understanding of REST API design principles. Bachelor's degree in Computer Science or equivalent."
        }
        res = self.client.post("/predict", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data["is_fake"])
        self.assertEqual(data["verdict"], "LEGITIMATE")
        self.assertGreaterEqual(data["legit_prob"], 60.0)
        self.assertEqual(data["risk"], "LOW")

    # 4. Suspicious sample posting prediction
    def test_04_suspicious_sample_prediction(self):
        payload = {
            "title": "Earn $5000/week from Home — No Experience Needed!",
            "location": "US, Remote",
            "description": "We are hiring data entry specialists to work from home. No experience required. You will earn guaranteed income of $5000 per week. Send money via western union for your starter kit. Bitcoin payments accepted. Click here to apply now and start earning fast!",
            "requirements": "Must be 18 or older. No skills needed. Just send $99 upfront fee for training materials and background check fee."
        }
        res = self.client.post("/predict", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["is_fake"])
        self.assertEqual(data["verdict"], "FAKE")
        self.assertGreaterEqual(data["fake_prob"], 70.0)
        self.assertEqual(data["risk"], "HIGH")
        self.assertGreaterEqual(len(data["red_flags"]), 3)

    # 5. Empty request returns HTTP 400
    def test_05_empty_request_returns_400(self):
        # Empty JSON
        res1 = self.client.post("/predict", json={})
        self.assertEqual(res1.status_code, 400)
        self.assertIn("error", res1.get_json())

        # Whitespace-only fields
        res2 = self.client.post("/predict", json={"title": "   ", "description": "\n\t"})
        self.assertEqual(res2.status_code, 400)
        self.assertIn("error", res2.get_json())

    # 6. Invalid JSON returns HTTP 400
    def test_06_invalid_json_returns_400(self):
        # Non-JSON content type
        res1 = self.client.post("/predict", data="hello world", content_type="text/plain")
        self.assertEqual(res1.status_code, 400)

        # JSON array instead of object
        res2 = self.client.post("/predict", json=["invalid", "array"])
        self.assertEqual(res2.status_code, 400)

    # 7. Non-string input returns HTTP 400
    def test_07_non_string_input_returns_400(self):
        payload = {
            "title": 12345,  # int instead of string
            "description": "Legitimate text description"
        }
        res = self.client.post("/predict", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("Expected a string", res.get_json()["error"])

        payload2 = {
            "title": "Valid title",
            "description": "Valid description",
            "stipend": {"amount": 500}  # dict instead of string
        }
        res2 = self.client.post("/predict", json=payload2)
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Expected a string", res2.get_json()["error"])

    # 8. Optional company/email/website fields are accepted
    def test_08_optional_fields_accepted(self):
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
        self.assertIn("verdict", data)
        self.assertEqual(data["verdict"], "LEGITIMATE")

        # Test optional field red-flag detection (free public email on corporate recruitment)
        payload_suspicious_email = {
            "title": "Data Analyst Intern",
            "description": "Assist with data visualization dashboards and data scrubbing.",
            "contact_email": "urgent-hiring-now@gmail.com",
            "stipend": "Pay 100 registration fee"
        }
        res_email = self.client.post("/predict", json=payload_suspicious_email)
        self.assertEqual(res_email.status_code, 200)
        data_email = res_email.get_json()
        flags_text = " ".join(data_email["red_flags"]).lower()
        self.assertTrue("email" in flags_text or "fee" in flags_text or "registration" in flags_text)

    # 9. Application can load model files when launched from a different working directory
    def test_09_different_working_directory_loading(self):
        import tempfile
        original_cwd = os.getcwd()
        try:
            temp_dir = tempfile.gettempdir()
            os.chdir(temp_dir)
            predictor = MLPredictor()
            res = predictor.predict(title="Intern", description="Software engineering task")
            self.assertIn("fake_prob", res)
            self.assertIn("verdict", res)
        finally:
            os.chdir(original_cwd)

    # 10. Existing frontend communicates correctly with the backend
    def test_10_frontend_backend_communication(self):
        payload = {
            "title": "Remote Data Entry Intern — Earn $5000/week (No Experience Needed)",
            "location": "Remote / Online",
            "description": "We are hiring data entry interns to work from home. No experience required. You will earn guaranteed income of $5000 per week. Send money via western union for your starter kit. Bitcoin payments accepted. Click here to apply now and start earning fast!",
            "requirements": "Must be 18 or older. No skills needed. Just send $99 upfront fee for training materials and background check fee.",
            "company_name": "Apex Global Solutions",
            "contact_email": "apex.hiring.team@gmail.com",
            "company_url": "http://apex-jobs-portal.xyz",
            "stipend": "$5,000 / week (Registration fee required)"
        }
        res = self.client.post("/predict", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["is_fake"])
        self.assertEqual(data["verdict"], "FAKE")
        self.assertEqual(data["risk"], "HIGH")
        self.assertGreater(data["fake_prob"], 90.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
