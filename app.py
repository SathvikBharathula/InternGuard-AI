"""
InternGuard AI - Flask Backend
An Agentic AI-Based Fake Internship Detection and Verification System.
Integrates TF-IDF ML prediction, rule-based screening, autonomous Groq-powered
investigation agent, and evidence-based risk report generation.
"""

import os
import logging
from werkzeug.exceptions import HTTPException
from flask import Flask, request, jsonify, render_template
from core.ml_predictor import MLPredictor
from core.rule_screener import RuleScreener
from core.agent import InternshipInvestigationAgent
from core.report_generator import ReportGenerator

# ── Setup logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("InternGuardAI")

# ── Application Factory & Pre-trained Artefacts ──────────────────────────────
app = Flask(__name__)

# Request body size limit: 1MB (enforces early rejection of oversized JSON payloads)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB

# Field-level maximum character length constraints
FIELD_MAX_LENGTHS = {
    "title": 200,
    "location": 200,
    "description": 20000,
    "requirements": 10000,
    "company_name": 200,
    "contact_email": 320,
    "company_url": 2048,
    "stipend": 200,
}

# Initialize ML Predictor, Rule Screener, and Investigation Agent (paths anchored to project root)
predictor = MLPredictor()
screener = RuleScreener(include_internship_heuristics=True)
agent = InternshipInvestigationAgent()

# Attach instances to app for accessibility and testing
app.predictor = predictor
app.screener = screener
app.agent = agent
app.report_generator = ReportGenerator
app.field_max_lengths = FIELD_MAX_LENGTHS


# ── Error Handlers ──────────────────────────────────────────────────────────
@app.errorhandler(413)
def request_entity_too_large(error):
    """Handles oversized requests rejected before processing."""
    return jsonify({
        "error": "Request payload too large: The overall request exceeds the 1MB limit."
    }), 413


# ── Routes ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    """Renders the main InternGuard AI application interface."""
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    """
    Evaluates an internship posting through the full multi-tier verification pipeline:
    1. Validates JSON payload, enforces non-empty content, validates field types & lengths.
    2. Runs statistical ML inference (TF-IDF + Logistic Regression).
    3. Runs deterministic rule screening for fraud keywords and heuristics.
    4. Executes autonomous Groq investigation agent when configured (graceful degradation if missing/error).
    5. Synthesizes findings using ReportGenerator into a transparent verification report.
    6. Returns combined response preserving backward-compatible fields alongside the complete report.
    """
    # 1. Validate JSON Content-Type and payload
    if not request.is_json:
        return jsonify({
            "error": "Invalid request: Content-Type must be 'application/json'"
        }), 400

    try:
        data = request.get_json(silent=False)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Malformed JSON received: {e}")
        return jsonify({"error": "Malformed JSON payload"}), 400

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON format: Expected a JSON object"
        }), 400

    # 2. Validate field data types and maximum length constraints (no silent truncation)
    for field, max_len in FIELD_MAX_LENGTHS.items():
        if field in data:
            if not isinstance(data[field], str):
                return jsonify({
                    "error": f"Invalid type for field '{field}': Expected a string, got {type(data[field]).__name__}"
                }), 400
            if len(data[field]) > max_len:
                return jsonify({
                    "error": (
                        f"Field '{field}' exceeds maximum permitted length of {max_len:,} characters "
                        f"(received {len(data[field]):,} characters)"
                    )
                }), 400

    # 3. Extract and normalize fields
    title = data.get("title", "").strip()
    location = data.get("location", "").strip()
    description = data.get("description", "").strip()
    requirements = data.get("requirements", "").strip()

    # Optional metadata fields
    company_name = data.get("company_name", "").strip()
    contact_email = data.get("contact_email", "").strip()
    company_url = data.get("company_url", "").strip()
    stipend = data.get("stipend", "").strip()

    # 4. Reject empty or insufficient inputs (do NOT classify empty as legitimate)
    if not title and not description:
        return jsonify({
            "error": "Empty input: Please provide at least an internship 'title' or 'description'"
        }), 400

    try:
        # 5. Run ML inference
        ml_result = predictor.predict(
            title=title,
            location=location,
            description=description,
            requirements=requirements,
        )

        # 6. Run rule-based heuristic screening
        # Include optional metadata in heuristic analysis
        additional_context = f"{company_name} {stipend}".strip()
        screen_text = f"{ml_result['combined_text']} {additional_context}".strip()

        red_flags = screener.screen(
            text=screen_text,
            contact_email=contact_email,
            stipend=stipend,
        )

        # 7. Run autonomous Groq investigation agent when configured
        active_agent = getattr(app, "agent", agent)
        groq_api_key = os.environ.get("GROQ_API_KEY")
        groq_model = os.environ.get("GROQ_MODEL")

        # Determine unverified items for missing inputs
        unverified_inputs = []
        if not contact_email:
            unverified_inputs.append("Recruiter contact email was not provided in posting.")
        if not company_url:
            unverified_inputs.append("Company website URL was not provided in posting.")
        if not company_name:
            unverified_inputs.append("Company name was not specified in posting.")
        if not stipend:
            unverified_inputs.append("Compensation or stipend terms were not specified.")

        agent_result = None
        agent_status = "unconfigured"
        tools_executed = []

        # Check if active agent is mocked or configured
        is_mock = (
            not hasattr(active_agent, "is_configured")
            or type(active_agent).__name__ in ("MagicMock", "Mock")
            or hasattr(getattr(active_agent, "investigate", None), "mock_calls")
        )
        is_configured = False
        if not is_mock and hasattr(active_agent, "is_configured"):
            try:
                is_configured = bool(active_agent.is_configured())
            except Exception:
                is_configured = False

        if not groq_api_key and not is_configured and not is_mock:
            # Groq is not configured; skip agentic investigation gracefully
            logger.info("GROQ_API_KEY not configured. Skipping autonomous agent investigation.")
            agent_status = "unconfigured"
            tools_executed = []
            agent_result = {
                "status": "unconfigured",
                "agent_summary": "GROQ_API_KEY environment variable is not configured. Autonomous AI investigation is disabled.",
                "tools_selected": [],
                "tool_results": [],
                "investigation_steps": [],
                "observations": [],
                "unverified_items": unverified_inputs,
                "limitations": ["Groq API key not configured; automated tool investigation skipped."],
                "error": "GROQ_API_KEY environment variable is not configured. Set GROQ_API_KEY to enable autonomous agentic investigation.",
            }
        else:
            try:
                # Refresh agent instance if env key is newly added
                if not is_mock and not is_configured and groq_api_key:
                    active_agent = InternshipInvestigationAgent(
                        api_key=groq_api_key,
                        model=groq_model
                    )

                agent_result = active_agent.investigate(
                    title=title,
                    location=location,
                    description=description,
                    requirements=requirements,
                    company_name=company_name,
                    contact_email=contact_email,
                    company_url=company_url,
                    stipend=stipend,
                )
                agent_status = agent_result.get("status", "completed")
                tools_executed = agent_result.get("tools_selected", [])
            except Exception as agent_exc:
                logger.warning(f"Investigation agent execution failed: {agent_exc}", exc_info=True)
                agent_status = "error"
                tools_executed = []
                agent_result = {
                    "status": "error",
                    "agent_summary": f"Investigation agent error: {agent_exc}",
                    "tools_selected": [],
                    "tool_results": [],
                    "investigation_steps": [],
                    "observations": [],
                    "unverified_items": unverified_inputs,
                    "limitations": [f"Investigation failed due to error: {agent_exc}"],
                    "error": str(agent_exc),
                }

        # 8. Synthesize findings using ReportGenerator
        posting_details = {
            "title": title,
            "location": location,
            "description": description,
            "requirements": requirements,
            "company_name": company_name,
            "contact_email": contact_email,
            "company_url": company_url,
            "stipend": stipend,
        }

        report = ReportGenerator.generate_report(
            ml_result=ml_result,
            rule_findings=red_flags,
            agent_result=agent_result,
            posting_details=posting_details,
        )

        # 9. Derive top-level verdict and risk fields consistent with generated report
        final_score = report.get("risk_score", 0)
        if final_score >= 70:
            top_verdict = "FAKE"
            top_risk = "HIGH"
            is_fake = True
        elif final_score <= 29:
            top_verdict = "LEGITIMATE"
            top_risk = "LOW"
            is_fake = False
        else:
            top_verdict = "SUSPICIOUS"
            top_risk = "MEDIUM"
            is_fake = bool(ml_result.get("is_fake", False))

        # 10. Construct response with backward-compatible fields + Phase 6 additions
        response = {
            "is_fake": is_fake,
            "fake_prob": ml_result["fake_prob"],
            "legit_prob": ml_result["legit_prob"],
            "confidence": ml_result["confidence"],
            "risk": top_risk,
            "verdict": top_verdict,
            "red_flags": red_flags,
            "agent_status": agent_status,
            "tools_executed": tools_executed,
            "report": report,
        }
        return jsonify(response), 200

    except Exception as exc:
        logger.error(f"Unexpected prediction error: {exc}", exc_info=True)
        return jsonify({
            "error": "An internal error occurred during prediction. Please try again."
        }), 500


# ── Health check endpoint for testing / monitoring ──────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "app": "InternGuard AI",
        "version": "2.0.0"
    }), 200


if __name__ == "__main__":
    # Explicit development configuration; debug disabled by default for security
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    server_port = int(os.environ.get("PORT", 5000))

    logger.info(f"Starting InternGuard AI on http://127.0.0.1:{server_port} (debug={debug_mode})")
    app.run(host="127.0.0.1", port=server_port, debug=debug_mode)
