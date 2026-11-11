"""
InternGuard AI - Phase 7 Input Size Limit Verification Suite
Tests:
1. Each of the 8 fields exceeding its server-side maximum character length (rejected with HTTP 400).
2. Inputs exactly at the permitted limit (boundary conditions pass validation).
3. Overall request body exceeding MAX_CONTENT_LENGTH (rejected with HTTP 413).
4. Verification that rejected requests never invoke the investigation agent.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import app as flask_module


class TestInputSizeLimits(unittest.TestCase):
    """Rigorous boundary and constraint testing for request and field sizes."""

    @classmethod
    def setUpClass(cls):
        flask_module.app.testing = True
        cls.client = flask_module.app.test_client()
        cls.limits = flask_module.FIELD_MAX_LENGTHS

    def test_01_each_field_exceeding_limit_rejected_400(self):
        """Verify each of the 8 input fields is rejected with HTTP 400 when exceeding its limit."""
        for field, max_len in self.limits.items():
            # Build payload with only this field oversized (title and description present as base)
            payload = {
                "title": "Valid Title",
                "description": "Valid Description",
            }
            # Add oversized field (max_len + 1 characters)
            payload[field] = "x" * (max_len + 1)

            res = self.client.post("/predict", json=payload)
            self.assertEqual(
                res.status_code,
                400,
                f"Field '{field}' with length {max_len + 1} was not rejected with HTTP 400"
            )
            data = res.get_json()
            self.assertIn("error", data)
            self.assertIn(f"Field '{field}' exceeds maximum permitted length", data["error"])
            self.assertIn(f"{max_len:,}", data["error"])

    def test_02_each_field_at_exact_permitted_limit_accepted(self):
        """Verify boundary condition: inputs exactly at the maximum length are accepted (HTTP 200)."""
        with patch.dict(os.environ, {}, clear=True):
            # Build a payload where every field is exactly at its permitted limit
            boundary_payload = {
                "title": "T" * self.limits["title"],
                "location": "L" * self.limits["location"],
                "description": "D" * self.limits["description"],
                "requirements": "R" * self.limits["requirements"],
                "company_name": "C" * self.limits["company_name"],
                "contact_email": ("e" * (self.limits["contact_email"] - len("@company.com"))) + "@company.com",
                "company_url": "https://www.example.com/" + ("u" * (self.limits["company_url"] - len("https://www.example.com/"))),
                "stipend": "S" * self.limits["stipend"],
            }

            # Verify exact lengths
            for f, expected_len in self.limits.items():
                self.assertEqual(len(boundary_payload[f]), expected_len, f"Field '{f}' not exactly at limit")

            res = self.client.post("/predict", json=boundary_payload)
            self.assertEqual(
                res.status_code,
                200,
                f"Payload with fields at exact limit was unexpectedly rejected: {res.get_json()}"
            )
            data = res.get_json()
            self.assertIn("report", data)
            self.assertIsInstance(data["report"]["risk_score"], int)

    def test_03_oversized_overall_request_body_rejected_413(self):
        """Verify request body exceeding 1MB is rejected with HTTP 413 before processing."""
        # Create an oversized payload > 1MB (e.g. 1.2MB)
        # Note: We send raw data to trigger Flask's MAX_CONTENT_LENGTH check
        large_padding = " " * (1024 * 1024 + 10240)  # > 1MB of whitespace in JSON
        raw_payload = f'{{"title": "Intern", "description": "Good desc", "padding": "{large_padding}"}}'

        res = self.client.post(
            "/predict",
            data=raw_payload,
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 413)
        data = res.get_json()
        self.assertIn("error", data)
        self.assertIn("Request payload too large", data["error"])

    def test_04_rejected_requests_do_not_invoke_agent_or_screener(self):
        """Confirm that oversized requests are rejected at validation and never invoke the ML predictor, rule screener, or agent."""
        mock_agent = MagicMock()
        mock_agent.is_configured.return_value = True
        mock_predictor = MagicMock()
        mock_screener = MagicMock()

        with patch.object(flask_module.app, "agent", mock_agent), \
             patch.object(flask_module, "predictor", mock_predictor), \
             patch.object(flask_module, "screener", mock_screener):
            # Submitting oversized title (201 chars, limit 200)
            oversized_payload = {
                "title": "A" * (self.limits["title"] + 1),
                "description": "Standard internship description."
            }
            res = self.client.post("/predict", json=oversized_payload)
            self.assertEqual(res.status_code, 400)

            # Confirm ML predictor, rule screener, and agent were never called
            mock_predictor.predict.assert_not_called()
            mock_screener.screen.assert_not_called()
            mock_agent.investigate.assert_not_called()

            # Submitting oversized description (20,001 chars, limit 20,000)
            oversized_desc_payload = {
                "title": "Valid Intern",
                "description": "D" * (self.limits["description"] + 1)
            }
            res2 = self.client.post("/predict", json=oversized_desc_payload)
            self.assertEqual(res2.status_code, 400)

            # Confirm none was called on oversized description either
            mock_predictor.predict.assert_not_called()
            mock_screener.screen.assert_not_called()
            mock_agent.investigate.assert_not_called()

    def test_05_no_silent_truncation_enforced(self):
        """Confirm that inputs exceeding limits are explicitly rejected, never silently truncated."""
        oversized_stipend = "$" + ("0" * 205)
        res = self.client.post("/predict", json={"title": "Intern", "description": "Desc", "stipend": oversized_stipend})
        self.assertEqual(res.status_code, 400)
        error_msg = res.get_json()["error"]
        self.assertIn("Field 'stipend' exceeds maximum permitted length of 200 characters", error_msg)
        self.assertIn("received 206 characters", error_msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
