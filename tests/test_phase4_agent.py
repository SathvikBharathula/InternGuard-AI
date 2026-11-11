"""
InternGuard AI - Phase 4 Agentic AI Test Suite
Comprehensive unit tests for the autonomous Groq-powered investigation agent:
- Configuration handling and graceful degradation when GROQ_API_KEY is missing
- Model availability verification without silent fallbacks
- Autonomous tool-calling workflow with genuine Groq function calling protocol
- Evidence collection and investigation output without final classification
- Handling of missing optional fields (email, website)
- Safe handling of tool execution errors without crashing
- Verification that complete investigation output is JSON-serializable
- Accurate preservation of original tool observations and evidence
- Safe handling of invalid or missing tool inputs
- Round limiting (strict 5-round cap) and infinite loop / duplicate call prevention
"""

import sys
import os
import unittest
import json
from unittest.mock import patch, MagicMock

# Ensure repository root is on sys.path
PROJECT_DIR = r"C:\Users\sathv\Desktop\MINI_PROJECT\AI-Powered-Fake-Job-Posting-Detection"
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from core.agent import InternshipInvestigationAgent, DEFAULT_GROQ_MODEL, MAX_INVESTIGATION_ROUNDS


class TestInternGuardAIAgentPhase4(unittest.TestCase):
    """Unit tests for the Groq-powered autonomous investigation agent."""

    # 1. Unconfigured API Key Handling
    def test_01_unconfigured_api_key_graceful_degradation(self):
        with patch.dict(os.environ, {}, clear=True):
            agent = InternshipInvestigationAgent(api_key=None)
            self.assertFalse(agent.is_configured())
            res = agent.investigate(
                title="AI Research Intern",
                description="Assist with machine learning experiments."
            )
            self.assertEqual(res["status"], "unconfigured")
            self.assertEqual(len(res["tools_selected"]), 0)
            self.assertIn("GROQ_API_KEY", res["error"])
            # Ensure no final classification keys exist
            self.assertNotIn("verdict", res)
            self.assertNotIn("risk_level", res)
            self.assertNotIn("confidence_score", res)

    # 2. Configured Model Availability Verification
    def test_02_model_availability_verified_successfully(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        agent = InternshipInvestigationAgent(
            api_key="gsk_mock_valid_key",
            model="llama-3.3-70b-versatile",
            client=mock_client
        )
        ok, msg, models = agent.check_model_availability()
        self.assertTrue(ok)
        self.assertIn("llama-3.3-70b-versatile", models)

    # 3. Model Unavailable Triggers Clear Error Without Silent Fallback
    def test_03_model_unavailable_fails_explicitly(self):
        mock_client = MagicMock()
        mock_model_1 = MagicMock()
        mock_model_1.id = "other-model-only"
        mock_client.models.list.return_value.data = [mock_model_1]

        agent = InternshipInvestigationAgent(
            api_key="gsk_mock_valid_key",
            model="llama-3.3-70b-versatile",
            client=mock_client
        )
        ok, msg, models = agent.check_model_availability()
        self.assertFalse(ok)
        self.assertIn("not available for this account", msg)
        self.assertIn("Configure GROQ_MODEL", msg)

        # Investigation must report error and not silently execute a fallback model
        res = agent.investigate(title="Intern", description="Test description")
        self.assertEqual(res["status"], "error")
        self.assertIn("not available", res["error"])

    # 4. Multi-round Autonomous Tool Calling & Evidence Gathering (No Classification)
    def test_04_genuine_tool_calling_workflow(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        # Round 1: Model requests tool calling for description analysis and payment request
        tool_call_1 = MagicMock()
        tool_call_1.id = "call_desc_001"
        tool_call_1.function.name = "analyze_internship_description"
        tool_call_1.function.arguments = json.dumps({
            "description": "Earn $5000 per week working from home. No interview needed. Guaranteed income."
        })

        tool_call_2 = MagicMock()
        tool_call_2.id = "call_pay_002"
        tool_call_2.function.name = "verify_payment_requests"
        tool_call_2.function.arguments = json.dumps({
            "text": "Send $99 upfront registration fee via western union.",
            "stipend": "$5000/week"
        })

        msg_round_1 = MagicMock()
        msg_round_1.tool_calls = [tool_call_1, tool_call_2]
        msg_round_1.content = None

        resp_round_1 = MagicMock()
        resp_round_1.choices = [MagicMock(message=msg_round_1)]

        # Round 2: Model evaluates tool observations and produces evidence summary without verdict
        msg_round_2 = MagicMock()
        msg_round_2.tool_calls = None
        msg_round_2.content = json.dumps({
            "agent_summary": "Investigation revealed explicit upfront registration fee demand ($99) and unrealistic weekly earnings promise.",
            "observations": [
                "Upfront registration fee of $99 demanded",
                "Unrealistic stipend promise of $5000/week",
                "Western Union wire transfer requested"
            ],
            "unverified_items": ["Recruiter contact email was not provided in posting."],
            "limitations": ["Company registration could not be verified due to missing website URL."]
        })

        resp_round_2 = MagicMock()
        resp_round_2.choices = [MagicMock(message=msg_round_2)]

        mock_client.chat.completions.create.side_effect = [resp_round_1, resp_round_2]

        agent = InternshipInvestigationAgent(
            api_key="gsk_mock_valid_key",
            model="llama-3.3-70b-versatile",
            client=mock_client
        )

        res = agent.investigate(
            title="Data Entry Intern",
            description="Earn $5000 per week working from home. No interview needed. Guaranteed income.",
            stipend="$5000/week"
        )

        self.assertEqual(res["status"], "completed")
        self.assertIn("analyze_internship_description", res["tools_selected"])
        self.assertIn("verify_payment_requests", res["tools_selected"])
        self.assertEqual(len(res["tool_results"]), 2)
        self.assertEqual(len(res["investigation_steps"]), 1)

        # STRICT PHASE 4 REQUIREMENT: Confirm no final verdicts or risk scores
        self.assertNotIn("verdict", res)
        self.assertNotIn("risk_level", res)
        self.assertNotIn("confidence_score", res)

        # Required fields check
        required_keys = {
            "status", "agent_summary", "tools_selected", "tool_results",
            "investigation_steps", "observations", "unverified_items", "limitations", "error"
        }
        self.assertTrue(required_keys.issubset(res.keys()))
        self.assertGreaterEqual(len(res["observations"]), 3)
        self.assertIn("registration fee", res["agent_summary"].lower())

    # 5. Missing Optional Email and Website Fields
    def test_05_missing_optional_email_and_website_fields(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        # Model requests description analysis only since email and website are missing
        tool_call = MagicMock()
        tool_call.id = "call_desc_only"
        tool_call.function.name = "analyze_internship_description"
        tool_call.function.arguments = json.dumps({"description": "Research internship description"})

        msg_1 = MagicMock(tool_calls=[tool_call], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Description analyzed; email and website were omitted.",
                "observations": ["Posting is brief."],
                "unverified_items": ["Email not provided", "Website not provided"],
                "limitations": []
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="gsk_mock_valid_key", client=mock_client)
        res = agent.investigate(
            title="Research Intern",
            description="Research internship description",
            contact_email="",  # Missing email
            company_url=""     # Missing website
        )

        # Tools selected must not include email or website verification
        self.assertNotIn("verify_email", res["tools_selected"])
        self.assertNotIn("verify_company_website", res["tools_selected"])

        # unverified_items must document that email and website were missing
        unverified_text = " ".join(res["unverified_items"]).lower()
        self.assertIn("email", unverified_text)
        self.assertIn("website", unverified_text)

    # 6. Tool Execution Errors Handled Gracefully Without Crashing
    def test_06_tool_execution_error_handled_gracefully(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        tool_call = MagicMock()
        tool_call.id = "call_err"
        tool_call.function.name = "verify_payment_requests"
        tool_call.function.arguments = json.dumps({"text": "Check fees"})

        msg_1 = MagicMock(tool_calls=[tool_call], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Investigation completed despite tool error.",
                "observations": ["Payment tool encountered an error"],
                "unverified_items": [],
                "limitations": ["Payment verification failed"]
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="gsk_mock_valid_key", client=mock_client)

        # Force tool to throw an unhandled exception
        with patch("core.agent.verify_payment_requests", side_effect=RuntimeError("Subsystem failure")):
            res = agent.investigate(title="Intern", description="Check fees")

        self.assertEqual(res["status"], "completed")
        self.assertEqual(len(res["tool_results"]), 1)
        err_out = res["tool_results"][0]["output"]
        self.assertEqual(err_out["status"], "error")
        self.assertIn("Subsystem failure", err_out["findings"][0]["message"])

    # 7. Complete Output is JSON-Serializable
    def test_07_complete_output_is_json_serializable(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        tool_call = MagicMock()
        tool_call.id = "call_1"
        tool_call.function.name = "analyze_internship_description"
        tool_call.function.arguments = json.dumps({"description": "Test internship description"})

        msg_1 = MagicMock(tool_calls=[tool_call], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Standard internship posting investigated.",
                "observations": ["Action verbs present"],
                "unverified_items": ["Email not provided"],
                "limitations": []
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="gsk_mock_valid_key", client=mock_client)
        res = agent.investigate(title="Intern", description="Test internship description")

        # Must serialize cleanly to JSON string without errors
        try:
            serialized = json.dumps(res)
            self.assertIsInstance(serialized, str)
            re_parsed = json.loads(serialized)
            self.assertEqual(re_parsed["status"], "completed")
        except TypeError as exc:
            self.fail(f"Agent output is not JSON-serializable: {exc}")

    # 8. Original Tool Observations are Accurately Preserved
    def test_08_original_tool_observations_accurately_preserved(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        tool_call = MagicMock()
        tool_call.id = "call_orig_01"
        tool_call.function.name = "verify_payment_requests"
        tool_call.function.arguments = json.dumps({"text": "Candidates must pay registration fee of $50"})

        msg_1 = MagicMock(tool_calls=[tool_call], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Payment demands verified.",
                "observations": ["Fee requested"],
                "unverified_items": [],
                "limitations": []
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="gsk_mock_valid_key", client=mock_client)
        res = agent.investigate(title="Intern", description="Candidates must pay registration fee of $50")

        # Verify tool_results retains exact original structure from verify_payment_requests
        tool_res = res["tool_results"][0]
        self.assertEqual(tool_res["tool"], "verify_payment_requests")
        raw_output = tool_res["output"]
        self.assertEqual(raw_output["tool"], "payment_verification")
        self.assertEqual(raw_output["status"], "completed")
        self.assertTrue(raw_output["is_suspicious"])
        self.assertIn("registration_fee", raw_output["details"]["categories_triggered"])
        self.assertEqual(raw_output["evidence"][0]["matched_term"], "registration fee")

    # 9. Invalid or Missing Tool Inputs Handled Safely
    def test_09_invalid_or_missing_tool_inputs_handled_safely(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        # Model passes empty / None inputs to tools
        call_empty_email = MagicMock()
        call_empty_email.id = "call_empty"
        call_empty_email.function.name = "verify_email"
        call_empty_email.function.arguments = json.dumps({"email": ""})

        msg_1 = MagicMock(tool_calls=[call_empty_email], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Empty tool input handled.",
                "observations": [],
                "unverified_items": ["Email empty"],
                "limitations": []
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="gsk_mock_valid_key", client=mock_client)
        res = agent.investigate(title="Intern", description="Test")

        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["tool_results"][0]["output"]["status"], "skipped")

    # 10. Infinite Loop and Duplicate Call Prevention
    def test_10_infinite_loop_and_duplicate_call_prevention(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        dup_call = MagicMock()
        dup_call.id = "dup_001"
        dup_call.function.name = "verify_payment_requests"
        dup_call.function.arguments = json.dumps({"text": "pay $50 fee"})

        msg_round = MagicMock(tool_calls=[dup_call], content=None)
        mock_client.chat.completions.create.return_value = MagicMock(choices=[MagicMock(message=msg_round)])

        agent = InternshipInvestigationAgent(
            api_key="gsk_mock_valid_key",
            client=mock_client,
            max_rounds=3
        )

        res = agent.investigate(title="Intern", description="pay $50 fee")
        self.assertEqual(len(res["investigation_steps"]), 3)
        # First call was executed; duplicate calls were intercepted
        self.assertEqual(res["investigation_steps"][0]["tool_calls"][0]["status"], "executed")
        self.assertEqual(res["investigation_steps"][1]["tool_calls"][0]["status"], "skipped_duplicate")
        self.assertEqual(res["tool_results"][1]["output"]["status"], "skipped")

    # 11. Strict Maximum Round Cap
    def test_11_strict_max_round_cap_enforced(self):
        agent = InternshipInvestigationAgent(api_key="test_key", max_rounds=15)
        self.assertLessEqual(agent.max_rounds, 10)
        agent2 = InternshipInvestigationAgent(api_key="test_key")
        self.assertEqual(agent2.max_rounds, MAX_INVESTIGATION_ROUNDS)

    # 12. Malformed Tool Arguments and Unknown Tool Handled Gracefully
    def test_12_malformed_arguments_and_unknown_tool_handled(self):
        mock_client = MagicMock()
        mock_model = MagicMock()
        mock_model.id = "llama-3.3-70b-versatile"
        mock_client.models.list.return_value.data = [mock_model]

        call_bad_json = MagicMock()
        call_bad_json.id = "call_bad"
        call_bad_json.function.name = "verify_payment_requests"
        call_bad_json.function.arguments = "{not-valid-json"

        call_unknown = MagicMock()
        call_unknown.id = "call_unk"
        call_unknown.function.name = "hack_into_corporate_database"
        call_unknown.function.arguments = "{}"

        msg_1 = MagicMock(tool_calls=[call_bad_json, call_unknown], content=None)
        msg_2 = MagicMock(
            tool_calls=None,
            content=json.dumps({
                "agent_summary": "Completed with partial tool telemetry.",
                "observations": ["Unknown tool rejected"],
                "unverified_items": [],
                "limitations": []
            })
        )

        mock_client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(message=msg_1)]),
            MagicMock(choices=[MagicMock(message=msg_2)]),
        ]

        agent = InternshipInvestigationAgent(api_key="test_key", client=mock_client)
        res = agent.investigate(title="Intern", description="Test")
        self.assertEqual(res["status"], "completed")

        unk_exec = next(t for t in res["tool_results"] if t["tool"] == "hack_into_corporate_database")
        self.assertEqual(unk_exec["output"]["status"], "error")


if __name__ == "__main__":
    print("\n=======================================================")
    print("RUNNING INTERNGUARD AI PHASE 4 REVISED TEST SUITE")
    print("=======================================================\n")
    unittest.main(verbosity=2)
