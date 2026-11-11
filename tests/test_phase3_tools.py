"""
InternGuard AI - Phase 3 Dedicated Test Suite
Comprehensive unit tests for the four independent Python verification tools:
1. Email Verification Tool
2. Payment Request Detection Tool
3. Internship Description Analysis Tool
4. Company Website Verification Tool (with SSRF Defense)

Mocks network and DNS operations to ensure deterministic, fast, offline execution.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import socket

# Ensure repository root is on sys.path
PROJECT_DIR = r"C:\Users\sathv\Desktop\MINI_PROJECT\AI-Powered-Fake-Job-Posting-Detection"
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core.tools.email_verifier import verify_email
from core.tools.payment_verifier import verify_payment_requests
from core.tools.description_analyzer import analyze_internship_description
from core.tools.website_verifier import verify_company_website


class TestEmailVerificationTool(unittest.TestCase):
    """Unit tests for Tool 1: Email Verification."""

    def test_01_valid_corporate_email(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
            res = verify_email("recruiter@datapulse.io", check_dns=True)
            self.assertEqual(res["status"], "completed")
            self.assertEqual(res["details"]["domain"], "datapulse.io")
            self.assertTrue(res["details"]["is_valid_format"])
            self.assertFalse(res["details"]["is_public_provider"])
            self.assertFalse(res["details"]["is_disposable"])
            self.assertFalse(res["is_suspicious"])

    def test_02_invalid_email_formats(self):
        for bad_email in ["notanemail", "missing@domain", "user@.com", "user@domain..com", "@nodomain"]:
            res = verify_email(bad_email, check_dns=False)
            self.assertTrue(res["is_suspicious"], f"Failed to flag invalid email: {bad_email}")
            self.assertFalse(res["details"]["is_valid_format"])

    def test_03_missing_or_empty_email(self):
        res1 = verify_email(None)
        self.assertEqual(res1["status"], "skipped")
        res2 = verify_email("   ")
        self.assertEqual(res2["status"], "skipped")

    def test_04_public_email_provider_is_info_not_fraud(self):
        for provider_email in ["hiring.team@gmail.com", "recruiter@yahoo.com", "student@outlook.com"]:
            res = verify_email(provider_email, check_dns=False)
            self.assertTrue(res["details"]["is_public_provider"])
            # STRICT REQUIREMENT: Must NOT classify solely as fake/suspicious
            self.assertFalse(res["is_suspicious"])
            findings_cats = [f["category"] for f in res["findings"]]
            self.assertIn("public_webmail", findings_cats)
            # Severity must be INFO
            self.assertEqual(res["findings"][0]["severity"], "INFO")

    def test_05_disposable_email_is_flagged_high(self):
        for throwaway in ["scam@tempmail.com", "recruiter@mailinator.com", "fake@sharklasers.com"]:
            res = verify_email(throwaway, check_dns=False)
            self.assertTrue(res["is_suspicious"])
            self.assertTrue(res["details"]["is_disposable"])
            findings_cats = [f["category"] for f in res["findings"]]
            self.assertIn("disposable_email", findings_cats)

    def test_06_domain_dns_resolution_failure(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
            res = verify_email("hr@thisdomainwillneverexist12345.com", check_dns=True)
            self.assertTrue(res["is_suspicious"])
            self.assertFalse(res["details"]["domain_resolves"])
            findings_cats = [f["category"] for f in res["findings"]]
            self.assertIn("domain_not_found", findings_cats)


class TestPaymentRequestDetectionTool(unittest.TestCase):
    """Unit tests for Tool 2: Payment Request Detection."""

    def test_01_detect_registration_fee(self):
        text = "Candidates are required to pay a registration fee of $50 before starting the project."
        res = verify_payment_requests(text)
        self.assertTrue(res["is_suspicious"])
        self.assertIn("registration_fee", res["details"]["categories_triggered"])
        self.assertGreaterEqual(res["details"]["explicit_demands_count"], 1)
        self.assertIn("$50", res["evidence"][0]["snippet"])

    def test_02_detect_security_deposit(self):
        text = "A refundable security deposit of $100 must be sent for the company laptop."
        res = verify_payment_requests(text)
        self.assertTrue(res["is_suspicious"])
        self.assertIn("security_deposit", res["details"]["categories_triggered"])
        self.assertIn("security deposit", res["evidence"][0]["matched_term"])

    def test_03_detect_training_materials_fee(self):
        text = "Selected applicants must purchase starter kit fee and training material fee."
        res = verify_payment_requests(text)
        self.assertTrue(res["is_suspicious"])
        self.assertIn("training_fee", res["details"]["categories_triggered"])

    def test_04_detect_suspicious_payment_instructions(self):
        text = "Send your payment via western union or wire transfer. Bitcoin payments also accepted."
        res = verify_payment_requests(text)
        self.assertTrue(res["is_suspicious"])
        self.assertIn("suspicious_payment_methods", res["details"]["categories_triggered"])
        self.assertGreaterEqual(res["details"]["suspicious_methods_count"], 2)

    def test_05_distinguish_negated_benign_fee_disclaimers(self):
        # Explicit false-positive avoidance requirement
        benign_texts = [
            "No registration fee is required for this internship.",
            "We never ask for fees or deposits from candidates.",
            "Zero application fees; 100% free of cost for all students.",
            "All training costs are covered by the employer.",
        ]
        for b_text in benign_texts:
            res = verify_payment_requests(b_text)
            self.assertFalse(res["is_suspicious"], f"False positive triggered on benign statement: {b_text}")
            self.assertGreaterEqual(res["details"]["negated_mentions_count"], 1)
            self.assertEqual(res["details"]["explicit_demands_count"], 0)

    def test_06_missing_input_handled(self):
        res = verify_payment_requests(None, stipend=None)
        self.assertEqual(res["status"], "skipped")


class TestInternshipDescriptionAnalysisTool(unittest.TestCase):
    """Unit tests for Tool 3: Internship Description Analysis."""

    def test_01_ordinary_legitimate_description(self):
        desc = (
            "We are seeking a Backend Engineering Intern to collaborate with our core product team. "
            "You will design scalable REST APIs, build robust data models, and test web services. "
            "Mentorship from senior engineers provided throughout the program."
        )
        res = analyze_internship_description(desc, title="Software Engineering Intern")
        self.assertEqual(res["status"], "completed")
        self.assertFalse(res["is_suspicious"])
        self.assertTrue(res["details"]["has_actionable_responsibilities"])

    def test_02_unrealistic_earnings_detection(self):
        desc = "Earn $5000 per week with guaranteed income working 3 hours a day from home. Make money fast!"
        res = analyze_internship_description(desc)
        self.assertTrue(res["is_suspicious"])
        self.assertTrue(res["details"]["unrealistic_earnings_detected"])
        # Verify explanation of why it matters is present
        self.assertIn("why_it_matters", res["findings"][0])

    def test_03_easy_selection_claims_detection(self):
        desc = "Instant selection without interview! 100% placement guarantee upon applying."
        res = analyze_internship_description(desc)
        self.assertTrue(res["is_suspicious"])
        self.assertTrue(res["details"]["easy_selection_detected"])

    def test_04_unclear_or_no_eligibility_requirements(self):
        desc = "Data entry intern needed. No skills required and no experience needed. Anyone can apply."
        res = analyze_internship_description(desc)
        self.assertTrue(res["is_suspicious"])
        self.assertTrue(res["details"]["unclear_eligibility_detected"])

    def test_05_urgency_pressure_tactics(self):
        desc = "Limited seats left! Apply immediately today. Offer expires in 2 hours. Click here now!"
        res = analyze_internship_description(desc)
        self.assertTrue(res["is_suspicious"])
        self.assertTrue(res["details"]["urgency_pressure_detected"])

    def test_06_short_description_not_labeled_fraudulent(self):
        # STRICT REQUIREMENT: Do not label fraudulent merely because description is short
        short_desc = "Summer research internship in applied statistics."
        res = analyze_internship_description(short_desc)
        self.assertTrue(res["details"]["is_brief_description"])
        # Must NOT be marked suspicious solely for brevity
        self.assertFalse(res["is_suspicious"])
        brevity_findings = [f for f in res["findings"] if f["category"] == "brevity_observation"]
        self.assertEqual(len(brevity_findings), 1)
        self.assertEqual(brevity_findings[0]["severity"], "INFO")


class TestCompanyWebsiteVerificationTool(unittest.TestCase):
    """Unit tests for Tool 4: Company Website Verification with SSRF Defense."""

    def test_01_valid_url_syntax(self):
        res = verify_company_website("https://datapulse.io", check_reachability=False)
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["details"]["is_valid_url"])
        self.assertEqual(res["details"]["scheme"], "https")
        self.assertEqual(res["details"]["hostname"], "datapulse.io")

    def test_02_forbidden_schemes_rejected(self):
        forbidden_urls = [
            "file:///etc/passwd",
            "ftp://files.company.com/report.pdf",
            "javascript:alert(1)",
            "gopher://evil.com",
            "data:text/html;base64,PHNjcmlwdD4=",
        ]
        for f_url in forbidden_urls:
            res = verify_company_website(f_url, check_reachability=False)
            self.assertTrue(res["is_suspicious"], f"Failed to reject forbidden scheme: {f_url}")
            categories = [f["category"] for f in res["findings"]]
            self.assertIn("forbidden_scheme", categories)

    def test_03_ssrf_blocking_localhost_and_loopback(self):
        loopback_targets = [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:5000",
            "https://127.0.0.1",
        ]
        for target in loopback_targets:
            res = verify_company_website(target, check_reachability=True)
            self.assertTrue(res["is_suspicious"], f"Failed to block loopback: {target}")
            self.assertFalse(res["details"]["ssrf_safe"])
            categories = [f["category"] for f in res["findings"]]
            self.assertIn("ssrf_security_block", categories)

    def test_04_ssrf_blocking_private_rfc1918_ips(self):
        with patch("socket.getaddrinfo") as mock_dns:
            # Domain looks public but DNS resolves to internal network
            mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80))]
            res = verify_company_website("http://intranet.company.internal", check_reachability=True)
            self.assertTrue(res["is_suspicious"])
            self.assertFalse(res["details"]["ssrf_safe"])
            self.assertIn("ssrf_security_block", [f["category"] for f in res["findings"]])

    def test_05_ssrf_blocking_cloud_metadata_ip(self):
        with patch("socket.getaddrinfo") as mock_dns:
            # Simulating AWS/GCP/Azure link-local metadata address 169.254.169.254
            mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
            res = verify_company_website("http://metadata.cloud.com", check_reachability=True)
            self.assertTrue(res["is_suspicious"])
            self.assertFalse(res["details"]["ssrf_safe"])
            self.assertIn("ssrf_security_block", [f["category"] for f in res["findings"]])

    def test_06_unreachable_website_and_404_handling(self):
        # 1. DNS failure
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Domain not found")):
            res = verify_company_website("http://nonexistent-domain-xyz987.com", check_reachability=True)
            self.assertTrue(res["is_suspicious"])
            self.assertFalse(res["details"]["is_reachable"])

        # 2. HTTP 404 response
        with patch("socket.getaddrinfo") as mock_dns, patch("http.client.HTTPSConnection") as mock_http:
            mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            mock_conn = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status = 404
            mock_resp.getheader.return_value = ""
            mock_resp.read.return_value = b"Not Found"
            mock_conn.getresponse.return_value = mock_resp
            mock_http.return_value = mock_conn

            res_404 = verify_company_website("https://example.com/careers-missing", check_reachability=True)
            self.assertTrue(res_404["is_suspicious"])
            self.assertEqual(res_404["details"]["http_status"], 404)
            self.assertIn("website_not_found", [f["category"] for f in res_404["findings"]])

    def test_07_safe_redirect_followed(self):
        with patch("socket.getaddrinfo") as mock_dns, patch("http.client.HTTPSConnection") as mock_https, patch("http.client.HTTPConnection") as mock_http:
            mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

            # First response: 301 to https://example.com/careers
            conn1 = MagicMock()
            resp1 = MagicMock()
            resp1.status = 301
            resp1.getheader.return_value = "https://example.com/careers"
            conn1.getresponse.return_value = resp1
            mock_http.return_value = conn1

            # Second response: 200 OK
            conn2 = MagicMock()
            resp2 = MagicMock()
            resp2.status = 200
            resp2.getheader.return_value = "text/html"
            resp2.read.return_value = b"<html><head><title>Example Careers Portal</title></head><body></body></html>"
            conn2.getresponse.return_value = resp2
            mock_https.return_value = conn2

            res = verify_company_website("http://example.com", check_reachability=True)
            self.assertTrue(res["details"]["is_reachable"])
            self.assertEqual(res["details"]["page_title"], "Example Careers Portal")
            self.assertIn("https://example.com/careers", res["details"]["redirect_history"])

    def test_08_unsafe_redirect_to_internal_ip_blocked(self):
        with patch("socket.getaddrinfo") as mock_dns, patch("http.client.HTTPConnection") as mock_http:
            # Initial domain is public
            def dns_side_effect(host, port, *args, **kwargs):
                if host == "safe-site.com":
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
                elif host == "internal-service.local":
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.100", 80))]
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

            mock_dns.side_effect = dns_side_effect

            # 302 redirecting to an internal hostname
            conn = MagicMock()
            resp = MagicMock()
            resp.status = 302
            resp.getheader.return_value = "http://internal-service.local/admin"
            conn.getresponse.return_value = resp
            mock_http.return_value = conn

            res = verify_company_website("http://safe-site.com", check_reachability=True)
            self.assertTrue(res["is_suspicious"])
            self.assertIn("redirect_ssrf_block", [f["category"] for f in res["findings"]])


if __name__ == "__main__":
    print("\n=======================================================")
    print("RUNNING INTERNGUARD AI PHASE 3 TOOLS TEST SUITE")
    print("=======================================================\n")
    unittest.main(verbosity=2)
