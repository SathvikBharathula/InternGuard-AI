"""
InternGuard AI - Phase 5 Unit Test Suite (Final Review Verified)
Tests evidence-based risk scoring, score breakdown with 75-point evidence cap,
conflicting fee evidence priority, and input validation separation.
"""

import os
import sys
import json
import unittest
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.report_generator import ReportGenerator, generate_report


class TestInternGuardAIPhase5Report(unittest.TestCase):
    """
    Comprehensive test suite verifying Phase 5 final review requirements:
    - 75-point evidence cap and 45-point financial exploitation cap
    - Explicit score breakdown with evidence_summary and transparent arithmetic
    - Conflicting fee evidence resolution (actual demand takes priority)
    - Score neutrality of disclaimers, malformed inputs, and security blocks
    """

    REQUIRED_REPORT_FIELDS = [
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
        "recommendations",
    ]

    def test_01_no_fee_disclaimer_does_not_reduce_score(self):
        """1. A no-fee disclaimer does NOT subtract points from the risk score (strict score neutrality)."""
        base_ml = {"fake_prob": 20.0}  # ml_score = 6.0 -> risk_score = 6

        # Case A: Ordinary posting without any disclaimer
        rep_without_disclaimer = generate_report(
            ml_result=base_ml,
            rule_findings=[],
            posting_details={"title": "Data Intern", "description": "Support daily data engineering tasks."},
        )

        # Case B: Posting containing explicit no-fee disclaimer
        rep_with_disclaimer = generate_report(
            ml_result=base_ml,
            rule_findings=[],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [{"category": "fee_disclaimer", "message": "No registration fees are charged."}]
                        },
                    }
                ],
            },
            posting_details={
                "title": "Data Intern",
                "description": "Support daily data tasks. Note: No registration fees are charged for this internship.",
            },
        )

        # Scores must be strictly identical: disclaimer must not subtract points
        self.assertEqual(rep_without_disclaimer["risk_score"], rep_with_disclaimer["risk_score"])
        # Mitigation adjustments must be empty (0.0 negative points)
        self.assertEqual(len(rep_with_disclaimer["score_breakdown"]["mitigation_adjustments"]), 0)

    def test_02_no_fee_disclaimer_suppresses_isolated_keyword_false_positive(self):
        """2. A no-fee disclaimer suppresses isolated keyword false positives without subtracting points."""
        base_ml = {"fake_prob": 15.0}  # ml_score = 4.5 -> risk_score = 4 (round half to even)

        # Without suppression: rule screener matches 'registration fee' keyword in isolation
        rep_false_positive = generate_report(
            ml_result=base_ml,
            rule_findings=["Internships charging a registration fee are typically fraudulent"],
            posting_details={"description": "We are hiring interns."},
        )
        self.assertGreaterEqual(rep_false_positive["risk_score"], 35)

        # With disclaimer present: rule screener fired because text said 'No registration fee'
        rep_suppressed = generate_report(
            ml_result=base_ml,
            rule_findings=["Internships charging a registration fee are typically fraudulent"],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [{"category": "fee_disclaimer", "message": "No registration fee is required."}]
                        },
                    }
                ],
            },
            posting_details={"description": "No registration fee is required for this internship."},
        )

        base_rep = generate_report(
            ml_result=base_ml,
            posting_details={"description": "No registration fee is required for this internship."},
        )

        # Advance fee must be suppressed: score remains base ML score
        self.assertEqual(rep_suppressed["risk_score"], base_rep["risk_score"])
        indicators = [item["indicator"] for item in rep_suppressed["score_breakdown"]["risk_indicators"]]
        self.assertNotIn("advance_fee_demand", indicators)

    def test_03_conflicting_fee_evidence_actual_demand_takes_priority(self):
        """3. Conflicting fee evidence: actual demand takes priority over 'no fee' disclaimer."""
        base_ml = {"fake_prob": 15.0}  # ml_score = 4.5

        # Subcase A: Text has 'no registration fee' disclaimer BUT explicitly demands a security deposit
        rep_security_deposit = generate_report(
            ml_result=base_ml,
            rule_findings=["Asking for a refundable/non-refundable security deposit is a scam indicator"],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [
                                {"category": "fee_disclaimer", "message": "No registration fees are charged."},
                                {"category": "security_deposit", "message": "Mandatory security deposit of $200 required."},
                            ]
                        },
                    }
                ],
            },
            posting_details={
                "description": "No registration fees are charged. However, selected candidates must pay a refundable security deposit of $200."
            },
        )

        # Advance fee demand MUST be flagged because actual demand overrides the disclaimer
        indicators_sd = [item["indicator"] for item in rep_security_deposit["score_breakdown"]["risk_indicators"]]
        self.assertIn("advance_fee_demand", indicators_sd)
        self.assertGreaterEqual(rep_security_deposit["risk_score"], 35)

        # Subcase B: Text has 'zero registration fees' BUT explicitly demands a training fee
        rep_training_fee = generate_report(
            ml_result=base_ml,
            rule_findings=["Training fee requests are suspicious"],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [
                                {"category": "fee_disclaimer", "message": "Zero registration fees."},
                                {"category": "training_fee", "message": "Applicants must pay a $100 training materials fee."},
                            ]
                        },
                    }
                ],
            },
            posting_details={
                "description": "Zero registration fees. Candidates must pay a $100 training fee for software tools."
            },
        )

        indicators_tf = [item["indicator"] for item in rep_training_fee["score_breakdown"]["risk_indicators"]]
        self.assertIn("advance_fee_demand", indicators_tf)
        self.assertGreaterEqual(rep_training_fee["risk_score"], 35)

    def test_04_financial_exploitation_retains_45_point_cap(self):
        """4. Financial exploitation retains strict 45-point cap when both advance fee and channel hit."""
        # advance_fee_demand = 35.0, suspicious_payment_channel = 25.0 -> uncapped = 60.0, capped at 45.0
        rep = generate_report(
            ml_result={"fake_prob": 10.0},  # ml_score = 3.0
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [
                                {"category": "registration_fee", "message": "Pay $100 registration fee."},
                                {"category": "suspicious_payment_channel", "message": "Send payment via Bitcoin."},
                            ]
                        },
                    }
                ],
            },
        )

        bd = rep["score_breakdown"]
        # Financial exploitation subtotal capped at 45.0
        fee_pts = next(i["points"] for i in bd["risk_indicators"] if i["indicator"] == "advance_fee_demand")
        channel_pts = next(i["points"] for i in bd["risk_indicators"] if i["indicator"] == "suspicious_payment_channel")
        self.assertEqual(fee_pts + channel_pts, 45.0)
        self.assertTrue(bd["evidence_summary"]["financial_exploitation_capped"])

    def test_05_overall_evidence_score_cap_at_75_points(self):
        """5. Combined evidence contribution must not exceed 75 points; explicitly shown in breakdown."""
        # Accumulate evidence well beyond 75 points:
        # advance_fee (35) + crypto channel (10 capped = 45 financial)
        # + disposable_email (25) + invalid_website (15) + easy_selection (10) + urgency (10) + vague_role (5)
        # Uncapped evidence sum = 45 + 25 + 15 + 10 + 10 + 5 = 110.0 points
        rep = generate_report(
            ml_result={"fake_prob": 50.0},  # ml_score = 15.0
            rule_findings=[
                "Internships charging a registration fee are typically fraudulent",
                "Western Union payment — common fraud pattern",
                "Earn money fast",
                "Unrealistic entry barrier",
                "Urgency/clickbait language detected",
                "Must be 18",
            ],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [
                                {"category": "registration_fee", "message": "Fee required"},
                                {"category": "suspicious_payment_channel", "message": "Crypto only"},
                            ]
                        },
                    },
                    {
                        "tool": "verify_email",
                        "output": {"findings": [{"category": "disposable_email", "message": "Temp mail"}]},
                    },
                    {
                        "tool": "verify_company_website",
                        "output": {"findings": [{"category": "domain_resolution_failure", "message": "NXDOMAIN host"}]},
                    },
                    {
                        "tool": "analyze_internship_description",
                        "output": {
                            "findings": [
                                {"category": "unrealistic_earnings", "message": "Earn 50k"},
                                {"category": "easy_selection", "message": "Instant hire"},
                                {"category": "urgency_pressure", "message": "Act now"},
                                {"category": "unclear_requirements", "message": "Vague tasks"},
                            ]
                        },
                    },
                ],
            },
        )

        bd = rep["score_breakdown"]
        ev_summary = bd["evidence_summary"]

        # 1. Uncapped evidence total must reflect the sum of all triggered indicators (> 75)
        self.assertGreater(ev_summary["uncapped_evidence_total"], 75.0)

        # 2. Evidence cap must be strictly 75.0
        self.assertEqual(ev_summary["evidence_cap"], 75.0)
        self.assertTrue(ev_summary["evidence_cap_applied"])

        # 3. Final evidence contribution must be strictly capped at 75.0
        self.assertEqual(ev_summary["final_evidence_contribution"], 75.0)

        # 4. Total before clamping: 15.0 (ML) + 75.0 (Capped Evidence) = 90.0
        expected_subtotal = round(bd["ml_contribution"]["points"] + ev_summary["final_evidence_contribution"], 1)
        self.assertEqual(bd["subtotal_before_clamping"], expected_subtotal)
        self.assertEqual(bd["subtotal_before_clamping"], 90.0)
        self.assertEqual(rep["risk_score"], 90)

    def test_06_malformed_email_syntax_does_not_increase_fraud_risk(self):
        """6. Malformed recruiter email syntax is reported as input validation issue, NOT fraud risk."""
        base_report = generate_report(
            ml_result={"fake_prob": 15.0},
            posting_details={"title": "Junior Developer"},
        )

        malformed_email_report = generate_report(
            ml_result={"fake_prob": 15.0},
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_email",
                        "output": {
                            "findings": [
                                {
                                    "category": "invalid_format",
                                    "severity": "HIGH",
                                    "message": "Email address 'user@@domain..com' has invalid RFC format.",
                                }
                            ],
                        },
                    }
                ],
            },
            posting_details={"title": "Junior Developer", "contact_email": "user@@domain..com"},
        )

        self.assertEqual(base_report["risk_score"], malformed_email_report["risk_score"])
        self.assertTrue(len(malformed_email_report["input_validation_events"]) > 0)
        self.assertEqual(malformed_email_report["input_validation_events"][0]["category"], "invalid_format")
        self.assertTrue(any("invalid" in u.lower() for u in malformed_email_report["unverified_items"]))

    def test_07_malformed_website_url_does_not_increase_fraud_risk(self):
        """7. Malformed website URL is reported as input validation issue, NOT fraud risk."""
        base_report = generate_report(
            ml_result={"fake_prob": 15.0},
            posting_details={"title": "Analyst"},
        )

        malformed_url_report = generate_report(
            ml_result={"fake_prob": 15.0},
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_company_website",
                        "output": {
                            "findings": [
                                {
                                    "category": "invalid_hostname",
                                    "severity": "HIGH",
                                    "message": "Website URL 'http://invalid..host' has malformed hostname.",
                                }
                            ],
                        },
                    }
                ],
            },
            posting_details={"title": "Analyst", "company_url": "http://invalid..host"},
        )

        self.assertEqual(base_report["risk_score"], malformed_url_report["risk_score"])
        self.assertTrue(len(malformed_url_report["input_validation_events"]) > 0)
        self.assertEqual(malformed_url_report["input_validation_events"][0]["category"], "invalid_hostname")
        self.assertTrue(any("invalid" in u.lower() for u in malformed_url_report["unverified_items"]))

    def test_08_confirmed_domain_failures_distinguished_from_timeouts(self):
        """8. Confirmed domain failures (NXDOMAIN) add points, while temporary DNS timeouts remain neutral."""
        base_ml = {"fake_prob": 10.0}  # ml_score = 3.0 -> risk_score = 3

        # Case A: Temporary DNS lookup timeout (must award 0 points)
        timeout_report = generate_report(
            ml_result=base_ml,
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_company_website",
                        "output": {
                            "findings": [{"category": "domain_resolution_failure", "message": "DNS resolution timed out after 2.5s"}],
                        },
                    }
                ],
            },
        )
        self.assertEqual(timeout_report["risk_score"], 3)
        self.assertEqual(len(timeout_report["score_breakdown"]["risk_indicators"]), 0)

        # Case B: Confirmed non-existent domain (NXDOMAIN)
        nxdomain_report = generate_report(
            ml_result=base_ml,
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_email",
                        "output": {
                            "findings": [
                                {
                                    "category": "domain_not_found",
                                    "severity": "HIGH",
                                    "message": "Domain 'nonexistentfakeco12345.org' does not exist (NXDOMAIN).",
                                }
                            ],
                        },
                    }
                ],
            },
        )
        # Adds 20 points -> 3.0 + 20.0 = 23.0 -> 23
        self.assertEqual(nxdomain_report["risk_score"], 23)
        indicators = [item["indicator"] for item in nxdomain_report["score_breakdown"]["risk_indicators"]]
        self.assertIn("invalid_or_nonexistent_email_domain", indicators)

    def test_09_score_breakdown_arithmetic_remains_correct(self):
        """9. Score breakdown arithmetic adds up exactly, including clamping and no negative mitigations."""
        report = generate_report(
            ml_result={"fake_prob": 42.0},  # ml_score = 12.6
            rule_findings=["Unrealistic entry barrier"],  # easy_selection = 10.0
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "analyze_internship_description",
                        "output": {
                            "findings": [{"category": "urgency_pressure", "message": "Urgent deadline pressure"}]  # 10.0
                        },
                    }
                ],
            },
        )

        bd = report["score_breakdown"]
        self.assertEqual(bd["mitigation_adjustments"], [])
        self.assertIn("evidence_summary", bd)

        ev_sum = bd["evidence_summary"]
        self.assertEqual(ev_sum["uncapped_evidence_total"], 20.0)
        self.assertEqual(ev_sum["final_evidence_contribution"], 20.0)
        self.assertFalse(ev_sum["evidence_cap_applied"])

        expected_subtotal = round(bd["ml_contribution"]["points"] + ev_sum["final_evidence_contribution"], 1)
        self.assertEqual(bd["subtotal_before_clamping"], expected_subtotal)
        self.assertEqual(report["risk_score"], bd["final_score"])
        self.assertEqual(bd["final_score"], int(round(max(0, min(100, expected_subtotal)))))

    def test_10_ml_output_never_appears_in_verified_indicators(self):
        """10. ML output never appears in verified indicators."""
        ml_result = {
            "is_fake": False,
            "fake_prob": 4.0,
            "legit_prob": 96.0,
            "confidence": 96.0,
            "risk": "LOW",
            "verdict": "LEGITIMATE",
        }
        report = generate_report(
            ml_result=ml_result,
            rule_findings=[],
            agent_result={"status": "completed", "tool_results": []},
            posting_details={"title": "Software Engineer Intern"},
        )

        self.assertIn("ml_assessment", report)
        for ind in report["verified_indicators"]:
            ind_lower = ind.lower()
            self.assertNotIn("machine learning", ind_lower)
            self.assertNotIn("ml model", ind_lower)
            self.assertNotIn("statistical", ind_lower)
            self.assertNotIn("fake probability", ind_lower)

    def test_11_http_200_and_mx_records_described_cautiously_zero_points(self):
        """11. HTTP 200 and MX records are described cautiously and award 0 negative points."""
        agent_result = {
            "status": "completed",
            "tool_results": [
                {
                    "tool": "verify_company_website",
                    "output": {"findings": [{"category": "valid_website", "message": "HTTP 200 received"}]},
                },
                {
                    "tool": "verify_email",
                    "output": {"findings": [{"category": "corporate_email", "message": "Valid MX records"}]},
                },
            ],
        }
        report = generate_report(
            ml_result={"fake_prob": 10.0},
            rule_findings=[],
            agent_result=agent_result,
            posting_details={"company_url": "https://example.com", "contact_email": "hr@example.com"},
        )

        verified_text = " ".join(report["verified_indicators"]).lower()
        self.assertIn("technical signal observed", verified_text)
        self.assertIn("does not confirm", verified_text)
        self.assertIn("not recruiter affiliation", verified_text)
        self.assertEqual(len(report["score_breakdown"]["mitigation_adjustments"]), 0)

    def test_12_json_serialization_and_benchmarks_pass(self):
        """12. Complete report is strictly JSON-serializable and standard risk benchmarks pass thresholds."""
        # Low risk benchmark
        low_rep = generate_report(
            ml_result={"fake_prob": 6.2, "legit_prob": 93.8, "risk": "LOW", "verdict": "LEGITIMATE"},
            rule_findings=[],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {"tool": "verify_email", "output": {"findings": [{"category": "corporate_email"}]}},
                    {"tool": "verify_company_website", "output": {"findings": [{"category": "valid_website"}]}},
                ],
            },
            posting_details={"title": "SWE Intern", "contact_email": "recruiter@enterprisetech.com"},
        )
        self.assertLessEqual(low_rep["risk_score"], 29)
        self.assertEqual(low_rep["risk_level"], "LIKELY LEGITIMATE")
        self.assertEqual(low_rep["verdict"], "LIKELY LEGITIMATE")

        # Medium risk benchmark
        med_rep = generate_report(
            ml_result={"fake_prob": 52.0, "legit_prob": 48.0, "risk": "MEDIUM", "verdict": "FAKE"},
            rule_findings=["Unrealistic entry barrier", "Urgency/clickbait language detected"],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "analyze_internship_description",
                        "output": {
                            "findings": [
                                {"category": "easy_selection", "message": "Guaranteed selection"},
                                {"category": "urgency_pressure", "message": "Urgent apply"},
                            ]
                        },
                    }
                ],
            },
        )
        self.assertGreaterEqual(med_rep["risk_score"], 30)
        self.assertLessEqual(med_rep["risk_score"], 69)
        self.assertEqual(med_rep["risk_level"], "SUSPICIOUS")

        # High risk benchmark
        high_rep = generate_report(
            ml_result={"fake_prob": 88.5, "legit_prob": 11.5, "risk": "HIGH", "verdict": "FAKE"},
            rule_findings=[
                "Internships charging a registration fee are typically fraudulent",
                "Western Union payment — common fraud pattern",
            ],
            agent_result={
                "status": "completed",
                "tool_results": [
                    {
                        "tool": "verify_payment_requests",
                        "output": {
                            "findings": [
                                {"category": "registration_fee", "message": "Fee required"},
                                {"category": "suspicious_payment_channel", "message": "Western union"},
                            ]
                        },
                    },
                    {
                        "tool": "verify_email",
                        "output": {"findings": [{"category": "disposable_email", "message": "Tempmail"}]},
                    },
                ],
            },
        )
        self.assertGreaterEqual(high_rep["risk_score"], 70)
        self.assertEqual(high_rep["risk_level"], "HIGH RISK")

        # Verify JSON serialization on high_rep
        for field in self.REQUIRED_REPORT_FIELDS:
            self.assertIn(field, high_rep)
        try:
            serialized = json.dumps(high_rep)
            self.assertIsInstance(serialized, str)
            deserialized = json.loads(serialized)
            self.assertEqual(deserialized["risk_score"], high_rep["risk_score"])
        except Exception as exc:
            self.fail(f"Serialization failed: {exc}")


if __name__ == "__main__":
    unittest.main()
