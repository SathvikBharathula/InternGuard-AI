"""
InternGuard AI - Autonomous Groq-Powered Investigation Agent
Performs multi-step, evidence-based internship verification by autonomously
selecting and executing verification tools using native Groq tool calling.

Phase 4 Scope: Strictly limited to investigation, tool selection, evidence
collection, and factual summarization. Final classification, verdicts,
risk scoring, and confidence scores are handled in Phase 5.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

import groq
from core.tools.email_verifier import verify_email
from core.tools.payment_verifier import verify_payment_requests
from core.tools.description_analyzer import analyze_internship_description
from core.tools.website_verifier import verify_company_website

logger = logging.getLogger("InternGuardAI.Agent")

# Default proposed Groq model
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
MAX_INVESTIGATION_ROUNDS = 5

# System prompt instructing the agent on role, tools, and evidence collection
SYSTEM_PROMPT = """You are the InternGuard AI Investigation Agent, an expert forensic investigator dedicated to inspecting internship postings, gathering evidence, and identifying suspicious indicators.

Your objective is to investigate an internship posting by autonomously selecting and calling verification tools, evaluating their findings, and providing a factual, evidence-based investigation summary.

Available Tools:
1. verify_email: Call ONLY when a recruiter or contact email is provided.
2. verify_payment_requests: Call when payment terms, registration fees, stipends, or deposits are mentioned or suspected.
3. analyze_internship_description: Call to evaluate responsibilities, selection claims, unrealistic promises, and urgency.
4. verify_company_website: Call ONLY when a company website URL is provided.

Guiding Rules:
- Only call tools relevant to the available posting data and investigation needs.
- Do NOT call verify_email if no email address was provided. Note it as unprovided / unverified.
- Do NOT call verify_company_website if no website URL was provided. Note it as unprovided / unverified.
- Do not repeat identical tool calls with the same arguments.
- Carefully inspect tool observations before deciding your next step.
- Missing information is NOT proof of fraud; report it objectively as missing or unverified.
- A public email provider (e.g. Gmail) is an observation, NEVER sole proof of fraud.
- The existence of a website or HTTPS does NOT prove a company is legitimate.
- Network timeouts or failed resolutions are inconclusive technical errors, NOT proof of fraud.
- Stop when you have gathered sufficient evidence to conclude your investigation.

Do NOT provide a final classification (such as FRAUDULENT, LEGITIMATE, or SUSPICIOUS), risk score, or confidence score. Your role is strictly to collect evidence, identify specific indicators, and summarize observations.

When you finish your investigation, provide your findings formatted as a JSON object:
{
    "agent_summary": "<concise summary of findings and evidence collected>",
    "observations": ["<key observation or red flag 1>", "<key observation or red flag 2>", ...],
    "unverified_items": ["<item that was missing or could not be verified>", ...],
    "limitations": ["<investigation limitation 1>", ...]
}
"""

# Tool schemas conforming to Groq/OpenAI tool calling specification
TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "verify_email",
            "description": "Verifies a recruiter or contact email address. Validates RFC format, checks DNS/MX records, and checks for disposable/temporary domains. Only call this if an email address is provided.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "The contact or recruiter email address to verify."
                    }
                },
                "required": ["email"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_payment_requests",
            "description": "Scans internship text and stipend fields for advance-fee demands, registration fees, security deposits, training charges, and suspicious payment channels (wire transfer, cryptocurrency, gift cards). Distinguishes demands from benign disclaimers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The internship description, requirements, or offer text to scan."
                    },
                    "stipend": {
                        "type": "string",
                        "description": "Optional stipend or compensation details."
                    }
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_internship_description",
            "description": "Analyzes the internship title, description, and requirements for structural clarity, operational action verbs, unrealistic earning promises, suspiciously easy selection claims, lack of prerequisites, and high-pressure urgency tactics.",
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "The primary internship description text."
                    },
                    "title": {
                        "type": "string",
                        "description": "Optional internship role title."
                    },
                    "requirements": {
                        "type": "string",
                        "description": "Optional prerequisite requirements or qualifications."
                    }
                },
                "required": ["description"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_company_website",
            "description": "Validates a company website URL with strict SSRF defense. Verifies URL protocol, DNS resolution, and reachability. Only call this if a company website URL is provided.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The company website URL to verify."
                    }
                },
                "required": ["url"]
            }
        }
    }
]


class InternshipInvestigationAgent:
    """
    Autonomous investigation agent powered by Groq.
    Dynamically decides tool execution sequence and synthesizes observations
    into an evidence-based investigation result without making final classification.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        client: Optional[groq.Groq] = None,
        max_rounds: int = MAX_INVESTIGATION_ROUNDS
    ):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.model_name = model or os.environ.get("GROQ_MODEL") or DEFAULT_GROQ_MODEL
        self.max_rounds = max(1, min(max_rounds, 10))
        self._cached_available_models: Optional[List[str]] = None

        if client is not None:
            self.client = client
        elif self.api_key:
            self.client = groq.Groq(api_key=self.api_key)
        else:
            self.client = None

        # Map function names to actual implementations
        self.available_tools = {
            "verify_email": verify_email,
            "verify_payment_requests": verify_payment_requests,
            "analyze_internship_description": analyze_internship_description,
            "verify_company_website": verify_company_website,
        }

    def is_configured(self) -> bool:
        """Checks if the Groq API key is present."""
        return bool(self.api_key and self.client)

    def check_model_availability(self) -> Tuple[bool, str, List[str]]:
        """
        Queries the Groq API to check whether the configured model is available.
        Does not silently substitute fallback models if the configured model is missing.
        """
        if not self.is_configured():
            return False, "GROQ_API_KEY is not configured.", []

        try:
            if self._cached_available_models is None:
                model_list_response = self.client.models.list()
                self._cached_available_models = [m.id for m in model_list_response.data]

            available_models = self._cached_available_models

            if self.model_name in available_models:
                return True, f"Model '{self.model_name}' is available.", available_models
            else:
                return (
                    False,
                    (
                        f"Configured Groq model '{self.model_name}' is not available for this account. "
                        f"Available models: {available_models}. "
                        "Configure GROQ_MODEL in your environment to select an active model."
                    ),
                    available_models,
                )
        except Exception as exc:
            logger.warning(f"Failed to query Groq model list: {exc}")
            return False, f"Error verifying Groq model availability: {exc}", []

    def investigate(
        self,
        title: str = "",
        location: str = "",
        description: str = "",
        requirements: str = "",
        company_name: str = "",
        contact_email: str = "",
        company_url: str = "",
        stipend: str = "",
        check_network: bool = True
    ) -> Dict[str, Any]:
        """
        Conducts an autonomous multi-round investigation using genuine Groq tool calling.
        Collects evidence without performing final classification (which belongs to Phase 5).

        Returns:
            Structured dictionary with:
            - status: "completed" | "error" | "unconfigured"
            - agent_summary: Summary of evidence and investigation
            - tools_selected: List of tool names called
            - tool_results: Granular outputs from each tool executed
            - investigation_steps: Multi-round telemetry of steps taken
            - observations: List of findings and signals collected
            - unverified_items: List of missing or unreachable items
            - limitations: Disclosed boundaries and technical constraints
            - error: Error description when status is not "completed"
        """
        # Determine initial unverified items based on missing input fields
        unverified_items: List[str] = []
        if not contact_email or not contact_email.strip():
            unverified_items.append("Recruiter contact email was not provided in posting.")
        if not company_url or not company_url.strip():
            unverified_items.append("Company website URL was not provided in posting.")
        if not company_name or not company_name.strip():
            unverified_items.append("Company name was not specified in posting.")
        if not stipend or not stipend.strip():
            unverified_items.append("Compensation or stipend terms were not specified.")

        # 1. Graceful exit if API key is not configured
        if not self.is_configured():
            return {
                "status": "unconfigured",
                "agent_summary": "GROQ_API_KEY environment variable is not configured. Autonomous AI investigation is disabled.",
                "tools_selected": [],
                "tool_results": [],
                "investigation_steps": [],
                "observations": [],
                "unverified_items": unverified_items,
                "limitations": ["Groq API key not configured; automated tool investigation skipped."],
                "error": "GROQ_API_KEY environment variable is not configured. Set GROQ_API_KEY to enable autonomous agentic investigation.",
            }

        # 2. Check model availability
        model_ok, model_msg, _ = self.check_model_availability()
        if not model_ok:
            return {
                "status": "error",
                "agent_summary": model_msg,
                "tools_selected": [],
                "tool_results": [],
                "investigation_steps": [],
                "observations": [],
                "unverified_items": unverified_items,
                "limitations": [model_msg],
                "error": model_msg,
            }

        # 3. Construct initial message with available details
        initial_prompt = self._build_investigation_prompt(
            title=title,
            location=location,
            description=description,
            requirements=requirements,
            company_name=company_name,
            contact_email=contact_email,
            company_url=company_url,
            stipend=stipend,
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": initial_prompt},
        ]

        tools_selected: List[str] = []
        tool_results: List[Dict[str, Any]] = []
        investigation_steps: List[Dict[str, Any]] = []
        executed_call_signatures = set()

        round_num = 0
        final_response_text = ""

        # 4. Multi-round tool-calling loop (capped at max_rounds)
        while round_num < self.max_rounds:
            round_num += 1
            logger.info(f"Groq agent investigation round {round_num}/{self.max_rounds}")

            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    tools=TOOLS_SCHEMA,
                    tool_choice="auto",
                    temperature=0.1,
                )
            except Exception as api_err:
                logger.error(f"Groq API call error in round {round_num}: {api_err}")
                return {
                    "status": "error",
                    "agent_summary": f"Investigation halted due to API error: {str(api_err)}",
                    "tools_selected": tools_selected,
                    "tool_results": tool_results,
                    "investigation_steps": investigation_steps,
                    "observations": [],
                    "unverified_items": unverified_items,
                    "limitations": [f"Groq API connection error: {str(api_err)}"],
                    "error": f"Groq API error: {str(api_err)}",
                }

            response_message = response.choices[0].message
            tool_calls = response_message.tool_calls or []

            # Case A: Model requested tool calls
            if tool_calls:
                messages.append(response_message)
                step_record = {
                    "round": round_num,
                    "tools_requested": [c.function.name for c in tool_calls],
                    "tool_calls": [],
                }

                for call in tool_calls:
                    fn_name = call.function.name
                    raw_args = call.function.arguments or "{}"

                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                        if not isinstance(args, dict):
                            args = {"value": args}
                    except json.JSONDecodeError as json_err:
                        args = {}
                        observation = {
                            "tool": fn_name,
                            "status": "error",
                            "is_suspicious": False,
                            "findings": [{
                                "category": "malformed_arguments",
                                "severity": "HIGH",
                                "message": f"Malformed tool arguments: {json_err}",
                            }],
                            "evidence": [],
                            "details": {"raw_arguments": str(raw_args)},
                            "limitations": ["Could not parse JSON arguments from model."],
                        }
                        tool_results.append({
                            "tool": fn_name,
                            "arguments": args,
                            "output": observation,
                        })
                        step_record["tool_calls"].append({
                            "tool": fn_name,
                            "call_id": call.id,
                            "status": "argument_error",
                        })
                        messages.append({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "name": fn_name,
                            "content": json.dumps(observation),
                        })
                        continue

                    # Check for unknown tool
                    if fn_name not in self.available_tools:
                        observation = {
                            "tool": fn_name,
                            "status": "error",
                            "is_suspicious": False,
                            "findings": [{
                                "category": "unknown_tool",
                                "severity": "HIGH",
                                "message": f"Unknown tool '{fn_name}'. Permitted tools: {list(self.available_tools.keys())}",
                            }],
                            "evidence": [],
                            "details": {},
                            "limitations": ["Model attempted to call an unregistered tool name."],
                        }
                        tool_status = "unknown_tool"
                    else:
                        # Prevent duplicate identical tool calls
                        call_signature = (fn_name, json.dumps(args, sort_keys=True))
                        if call_signature in executed_call_signatures:
                            observation = {
                                "tool": fn_name,
                                "status": "skipped",
                                "is_suspicious": False,
                                "findings": [],
                                "evidence": [],
                                "details": {},
                                "limitations": [f"Tool '{fn_name}' was already executed with identical arguments in a previous turn."],
                            }
                            tool_status = "skipped_duplicate"
                        else:
                            executed_call_signatures.add(call_signature)
                            if fn_name not in tools_selected:
                                tools_selected.append(fn_name)

                            # Execute tool safely
                            observation = self._execute_tool(
                                fn_name=fn_name,
                                args=args,
                                check_network=check_network,
                            )
                            tool_status = "executed"

                    # Preserve original tool output as evidence
                    tool_results.append({
                        "tool": fn_name,
                        "arguments": args,
                        "output": observation,
                    })

                    step_record["tool_calls"].append({
                        "tool": fn_name,
                        "call_id": call.id,
                        "status": tool_status,
                    })

                    # Feed tool observation back to model
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "name": fn_name,
                        "content": json.dumps(observation, default=str),
                    })

                investigation_steps.append(step_record)

            # Case B: Model did not request tool calls; it produced its conclusion
            else:
                final_response_text = response_message.content or ""
                break

        # If loop reached max rounds without final text, request synthesis
        if not final_response_text:
            try:
                synthesis_resp = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.1,
                )
                final_response_text = synthesis_resp.choices[0].message.content or ""
            except Exception as syn_err:
                logger.warning(f"Error during final synthesis request: {syn_err}")
                final_response_text = "Investigation concluded after reaching iteration limit."

        # 5. Parse and structure the final evidence report (NO verdict / risk / confidence)
        agent_summary, observations, final_unverified, limitations = self._parse_final_report(
            response_text=final_response_text,
            tool_results=tool_results,
            unverified_defaults=unverified_items,
        )

        return {
            "status": "completed",
            "agent_summary": agent_summary,
            "tools_selected": tools_selected,
            "tool_results": tool_results,
            "investigation_steps": investigation_steps,
            "observations": observations,
            "unverified_items": final_unverified,
            "limitations": limitations,
            "error": None,
        }

    def _execute_tool(
        self,
        fn_name: str,
        args: Dict[str, Any],
        check_network: bool = True
    ) -> Dict[str, Any]:
        """Safely executes a verified tool with argument validation and network controls."""
        try:
            if fn_name == "verify_email":
                email = args.get("email")
                if email is not None:
                    email = str(email).strip()
                return verify_email(email=email, check_dns=check_network)

            elif fn_name == "verify_payment_requests":
                text = args.get("text")
                if text is not None:
                    text = str(text).strip()
                stipend = args.get("stipend")
                if stipend is not None:
                    stipend = str(stipend).strip()
                return verify_payment_requests(text=text, stipend=stipend)

            elif fn_name == "analyze_internship_description":
                desc = args.get("description")
                if desc is not None:
                    desc = str(desc).strip()
                title = args.get("title")
                if title is not None:
                    title = str(title).strip()
                reqs = args.get("requirements")
                if reqs is not None:
                    reqs = str(reqs).strip()
                return analyze_internship_description(description=desc, title=title, requirements=reqs)

            elif fn_name == "verify_company_website":
                url = args.get("url")
                if url is not None:
                    url = str(url).strip()
                return verify_company_website(url=url, check_reachability=check_network)

            else:
                return {
                    "tool": fn_name,
                    "status": "error",
                    "is_suspicious": False,
                    "findings": [{
                        "category": "unknown_tool",
                        "severity": "HIGH",
                        "message": f"Tool '{fn_name}' execution handler not implemented.",
                    }],
                    "evidence": [],
                    "details": {},
                    "limitations": ["Unimplemented tool called."],
                }

        except Exception as exc:
            logger.error(f"Error executing tool '{fn_name}': {exc}", exc_info=True)
            return {
                "tool": fn_name,
                "status": "error",
                "is_suspicious": False,
                "findings": [{
                    "category": "tool_execution_error",
                    "severity": "HIGH",
                    "message": f"Tool '{fn_name}' execution failed: {type(exc).__name__}: {str(exc)}",
                }],
                "evidence": [],
                "details": {"error": str(exc)},
                "limitations": [f"Execution of '{fn_name}' failed due to internal error."],
            }

    def _build_investigation_prompt(
        self,
        title: str,
        location: str,
        description: str,
        requirements: str,
        company_name: str,
        contact_email: str,
        company_url: str,
        stipend: str,
    ) -> str:
        """Constructs an objective summary of provided vs missing posting details."""
        lines = [
            "Please investigate the following internship posting for fraud or legitimacy.",
            "",
            "=== Provided Posting Details ===",
            f"Title: {title or '[NOT PROVIDED]'}",
            f"Location: {location or '[NOT PROVIDED]'}",
            f"Description: {description or '[NOT PROVIDED]'}",
            f"Requirements: {requirements or '[NOT PROVIDED]'}",
            f"Company Name: {company_name or '[NOT PROVIDED]'}",
            f"Recruiter Email: {contact_email or '[NOT PROVIDED]'}",
            f"Company Website: {company_url or '[NOT PROVIDED]'}",
            f"Stipend / Compensation: {stipend or '[NOT PROVIDED]'}",
            "",
            "Instructions:",
            "1. Review the details above.",
            "2. Decide which verification tools are necessary and relevant to run.",
            "3. If email or website is not provided, do not run those tools; report them as unverified.",
            "4. Call the selected tools to inspect evidence.",
            "5. Synthesize findings into an evidence summary without making final classifications.",
        ]
        return "\n".join(lines)

    def _parse_final_report(
        self,
        response_text: str,
        tool_results: List[Dict[str, Any]],
        unverified_defaults: List[str]
    ) -> Tuple[str, List[str], List[str], List[str]]:
        """
        Parses the model's final response into structured evidence summaries:
        agent_summary, observations, unverified_items, limitations.
        No verdicts, risk scores, or confidence scores are produced.
        """
        json_obj = None
        clean_text = response_text.strip()

        # Try direct JSON parsing
        try:
            json_obj = json.loads(clean_text)
        except Exception:
            pass

        # Try regex extract
        if not json_obj:
            match = re.search(r"\{[\s\S]*\}", clean_text)
            if match:
                try:
                    json_obj = json.loads(match.group(0))
                except Exception:
                    pass

        # Extract findings and limitations from all tool results
        tool_observations: List[str] = []
        tool_limitations: List[str] = []
        for tr in tool_results:
            out = tr.get("output", {})
            if isinstance(out, dict):
                for f in out.get("findings", []):
                    msg = f.get("message") if isinstance(f, dict) else str(f)
                    if msg and msg not in tool_observations:
                        tool_observations.append(msg)
                for lim in out.get("limitations", []):
                    if lim and lim not in tool_limitations:
                        tool_limitations.append(lim)

        if isinstance(json_obj, dict):
            summary = json_obj.get("agent_summary") or json_obj.get("summary") or clean_text
            model_obs = json_obj.get("observations") or json_obj.get("key_findings") or []
            if isinstance(model_obs, list):
                all_obs = list(dict.fromkeys(model_obs + tool_observations))
            else:
                all_obs = tool_observations

            model_unverified = json_obj.get("unverified_items", [])
            if isinstance(model_unverified, list):
                all_unverified = list(dict.fromkeys(unverified_defaults + model_unverified))
            else:
                all_unverified = list(unverified_defaults)

            model_lims = json_obj.get("limitations", [])
            if isinstance(model_lims, list):
                all_lims = list(dict.fromkeys(tool_limitations + model_lims))
            else:
                all_lims = tool_limitations

            return str(summary), all_obs, all_unverified, all_lims

        # Fallback if text was not JSON
        return clean_text, tool_observations, list(unverified_defaults), tool_limitations
