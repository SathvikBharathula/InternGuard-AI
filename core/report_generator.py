"""
InternGuard AI - Evidence-Based Risk Scoring and Verification Report Generator

Synthesizes multiple evidence streams:
1. Machine Learning prediction (core.ml_predictor)
2. Deterministic rule-based screening (core.rule_screener)
3. Autonomous Groq-powered investigation agent results (core.agent / core.tools)
4. Posting metadata and missing information

SCORING FORMULATION & ARCHITECTURE (FINAL REVISED):
===================================================
1. Total Risk Score Range: [0, 100]
   - Higher scores indicate greater fraud risk.
   - Classification Thresholds:
     * 0 to 29:   LIKELY LEGITIMATE (Low Risk Assessment - not a guarantee)
     * 30 to 69:  SUSPICIOUS
     * 70 to 100: HIGH RISK

2. Separation of Technical Verification from Proof of Legitimacy:
   - Technical reachability (HTTP 200, valid DNS/MX) confirms network delivery
     capability only, NOT corporate legitimacy or recruiter affiliation.
   - Technical signals award 0.0 negative risk points to avoid unjustified confidence.
   - Verified indicators are strictly limited to facts checked by tools and describe
     exactly what was tested without claiming verified company identity.
   - ML predictions are NEVER included in verified_indicators; they remain in ml_assessment.

3. Benign Fee Disclaimer Policy (Strict Score Neutrality):
   - Explicit zero-fee statements (e.g. "No registration fees are charged") do NOT
     subtract points from the risk score (0.0 negative mitigation points).
   - They strictly serve to suppress false-positive advance-fee findings when the context
     confirms that no fee is requested.
   - A disclaimer must never be treated as proof of employer legitimacy.

4. Separation of Input Validation from Confirmed Domain Failures:
   - Malformed recruiter email syntax (invalid_format) is an input-validation issue,
     NOT fraud evidence (0.0 fraud risk points).
   - Malformed website URLs (invalid_hostname) are input-validation issues (0.0 fraud risk points).
   - Both are recorded under input_validation_events, unverified_items, and limitations.
   - ONLY confirmed domain failures (NXDOMAIN) are considered as risk indicators.
   - DNS timeouts and temporary network failures remain neutral (0.0 points).

5. Separation of Application Security Events from Internship Fraud Risk:
   - SSRF attempts, private IP targets (RFC 1918, loopback, cloud metadata), and
     dangerous URI schemes (javascript:, file:) are blocked by security controls.
   - Recorded under security_events, limitations, and unverified_items (0.0 fraud risk points).

6. Explicit Score Breakdown:
   - Reports include an explicit, JSON-serializable `score_breakdown` field.
   - Itemizes: ml_contribution, risk_indicators, mitigation_adjustments ([]),
     subtotal_before_clamping, final_score, and an exact reconciliation summary.
   - The breakdown exactly sums up to the final score after clamping.
"""

import json
from typing import Dict, Any, List, Optional, Tuple, Set


class ReportGenerator:
    """
    Synthesizes ML predictions, rule-based heuristics, and forensic tool findings
    into a structured, explainable, and reproducible internship verification report.
    """

    # Classification Thresholds
    LEGITIMATE_THRESHOLD_MAX = 29
    SUSPICIOUS_THRESHOLD_MAX = 69

    # Canonical Category Weights
    WEIGHT_ADVANCE_FEE = 35.0
    WEIGHT_PAYMENT_CHANNEL = 25.0
    CAP_FINANCIAL_EXPLOITATION = 45.0
    CAP_COMBINED_EVIDENCE = 75.0
    WEIGHT_DISPOSABLE_EMAIL = 25.0
    WEIGHT_NONEXISTENT_EMAIL = 20.0
    WEIGHT_UNVERIFIED_CHAT = 15.0
    WEIGHT_UNREALISTIC_EARNINGS = 15.0
    WEIGHT_INVALID_WEBSITE = 15.0
    WEIGHT_EASY_SELECTION = 10.0
    WEIGHT_URGENCY_PRESSURE = 10.0
    WEIGHT_VAGUE_ROLE = 5.0

    # ML Component Maximum Weight
    ML_MAX_POINTS = 30.0

    @classmethod
    def generate_report(
        cls,
        ml_result: Optional[Dict[str, Any]] = None,
        rule_findings: Optional[List[str]] = None,
        agent_result: Optional[Dict[str, Any]] = None,
        posting_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive, transparent verification report with explicit score breakdown.
        """
        posting_details = posting_details or {}
        rule_findings = rule_findings or []

        # 1. Evaluate ML Prediction (strictly statistical signal)
        ml_score, ml_assessment = cls._evaluate_ml(ml_result)

        # 2. Extract and organize forensic tool evidence from agent results
        tool_findings, tool_limitations, tool_unverified, tool_results_clean = (
            cls._extract_agent_data(agent_result)
        )

        # 3. Separate application security events and input validation issues from fraud risk
        (
            security_events,
            input_validation_events,
            filtered_tool_findings,
        ) = cls._separate_non_fraud_events(tool_findings)

        # 4. Deduplicate evidence across rules and tools into canonical categories
        canonical_hits, technical_observations = cls._map_canonical_evidence(
            rule_findings=rule_findings,
            tool_findings=filtered_tool_findings,
            agent_result=agent_result,
            posting_details=posting_details,
        )

        # 5. Compute deterministic score components and explicit breakdown
        (
            evidence_score,
            score_breakdown,
            final_risk_score,
        ) = cls._compute_scores_and_breakdown(
            ml_score=ml_score,
            fake_prob=ml_assessment.get("fake_probability", 0.0),
            canonical_hits=canonical_hits,
        )

        # 6. Determine risk level and verdict
        if final_risk_score <= cls.LEGITIMATE_THRESHOLD_MAX:
            risk_level = "LIKELY LEGITIMATE"
            verdict = "LIKELY LEGITIMATE"
        elif final_risk_score <= cls.SUSPICIOUS_THRESHOLD_MAX:
            risk_level = "SUSPICIOUS"
            verdict = "SUSPICIOUS"
        else:
            risk_level = "HIGH RISK"
            verdict = "HIGH RISK"

        # 7. Build indicators, unverified items, and limitations
        # Note: ML predictions are NEVER included in verified_indicators
        verified_indicators = cls._build_verified_indicators(
            technical_observations=technical_observations,
            posting_details=posting_details,
            tool_findings=tool_findings,
        )
        suspicious_indicators = cls._build_suspicious_indicators(canonical_hits, ml_score)
        unverified_items = cls._build_unverified_items(
            posting_details=posting_details,
            agent_result=agent_result,
            tool_unverified=tool_unverified,
            security_events=security_events,
            input_validation_events=input_validation_events,
        )
        limitations = cls._build_limitations(
            agent_result=agent_result,
            tool_limitations=tool_limitations,
            posting_details=posting_details,
            security_events=security_events,
            input_validation_events=input_validation_events,
        )

        # 8. Generate targeted, actionable recommendations
        recommendations = cls._generate_recommendations(
            risk_level=risk_level,
            canonical_hits=canonical_hits,
            unverified_items=unverified_items,
            posting_details=posting_details,
            security_events=security_events,
            input_validation_events=input_validation_events,
        )

        # 9. Compose explainable narrative summary
        summary = cls._compose_summary(
            risk_score=final_risk_score,
            risk_level=risk_level,
            ml_score=ml_score,
            canonical_hits=canonical_hits,
            technical_observations=technical_observations,
            unverified_items=unverified_items,
        )

        rule_based_findings = [str(r) for r in rule_findings]

        report = {
            "risk_score": final_risk_score,
            "risk_level": risk_level,
            "verdict": verdict,
            "summary": summary,
            "score_breakdown": score_breakdown,
            "ml_assessment": ml_assessment,
            "rule_based_findings": rule_based_findings,
            "investigation_findings": filtered_tool_findings,
            "security_events": security_events,
            "input_validation_events": input_validation_events,
            "verified_indicators": verified_indicators,
            "suspicious_indicators": suspicious_indicators,
            "unverified_items": unverified_items,
            "limitations": limitations,
            "recommendations": recommendations,
        }

        # Ensure complete JSON serializability (handling numpy/custom objects)
        return json.loads(json.dumps(report, default=str))

    @classmethod
    def _evaluate_ml(cls, ml_result: Optional[Dict[str, Any]]) -> Tuple[float, Dict[str, Any]]:
        """Evaluates ML result, producing safe score contribution and assessment dict."""
        if not isinstance(ml_result, dict) or not ml_result:
            return 0.0, {
                "status": "unavailable",
                "message": "ML statistical model evaluation was not provided.",
                "fake_probability": 0.0,
                "score_contribution": 0.0,
            }

        fake_prob = ml_result.get("fake_prob")
        try:
            fake_prob_val = float(fake_prob) if fake_prob is not None else 0.0
        except (TypeError, ValueError):
            fake_prob_val = 0.0

        legit_prob = ml_result.get("legit_prob")
        try:
            legit_prob_val = float(legit_prob) if legit_prob is not None else 100.0 - fake_prob_val
        except (TypeError, ValueError):
            legit_prob_val = 100.0 - fake_prob_val

        # ML contributes up to ML_MAX_POINTS
        ml_score = round((max(0.0, min(100.0, fake_prob_val)) / 100.0) * cls.ML_MAX_POINTS, 1)

        assessment = {
            "status": "completed",
            "fake_probability": round(fake_prob_val, 1),
            "legitimate_probability": round(legit_prob_val, 1),
            "confidence": float(ml_result.get("confidence", max(fake_prob_val, legit_prob_val))),
            "model_risk": str(ml_result.get("risk", "UNKNOWN")),
            "model_verdict": str(ml_result.get("verdict", "UNKNOWN")),
            "score_contribution": ml_score,
            "methodology_note": "Statistical signal based on training text n-grams. Does not constitute verified factual proof of legitimacy or fraud.",
        }
        return ml_score, assessment

    @classmethod
    def _extract_agent_data(
        cls, agent_result: Optional[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[str], List[str], List[Dict[str, Any]]]:
        """Extracts tool findings, limitations, and unverified elements from agent result."""
        tool_findings: List[Dict[str, Any]] = []
        tool_limitations: List[str] = []
        tool_unverified: List[str] = []
        clean_tool_results: List[Dict[str, Any]] = []

        if not isinstance(agent_result, dict):
            return tool_findings, tool_limitations, tool_unverified, clean_tool_results

        raw_tool_results = agent_result.get("tool_results", [])
        if isinstance(raw_tool_results, list):
            for tr in raw_tool_results:
                if not isinstance(tr, dict):
                    continue
                clean_tool_results.append(tr)
                tool_name = str(tr.get("tool", "unknown_tool"))
                out = tr.get("output", {})
                if isinstance(out, dict):
                    for f in out.get("findings", []):
                        if isinstance(f, dict):
                            finding_record = {
                                "tool": tool_name,
                                "category": str(f.get("category", "general")),
                                "severity": str(f.get("severity", "INFO")),
                                "message": str(f.get("message", "")),
                                "evidence": f.get("evidence", []),
                            }
                            tool_findings.append(finding_record)
                    for lim in out.get("limitations", []):
                        if lim and str(lim) not in tool_limitations:
                            tool_limitations.append(str(lim))

        agent_unverified = agent_result.get("unverified_items", [])
        if isinstance(agent_unverified, list):
            for u in agent_unverified:
                if u and str(u) not in tool_unverified:
                    tool_unverified.append(str(u))

        agent_limitations = agent_result.get("limitations", [])
        if isinstance(agent_limitations, list):
            for lim in agent_limitations:
                if lim and str(lim) not in tool_limitations:
                    tool_limitations.append(str(lim))

        return tool_findings, tool_limitations, tool_unverified, clean_tool_results

    @classmethod
    def _separate_non_fraud_events(
        cls, tool_findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Separates application security events (SSRF, blocked IPs) and input validation issues
        (malformed email syntax, malformed URLs) from internship fraud risk.
        Both categories contribute 0.0 fraud risk points.
        """
        security_events: List[Dict[str, Any]] = []
        input_validation_events: List[Dict[str, Any]] = []
        filtered_tool_findings: List[Dict[str, Any]] = []

        ssrf_categories = {
            "forbidden_scheme",
            "blocked_internal_ip",
            "blocked_hostname",
            "blocked_redirect",
        }
        input_validation_categories = {
            "invalid_format",     # Malformed email syntax
            "invalid_hostname",   # Malformed website URL syntax
        }

        for finding in tool_findings:
            cat = finding.get("category")
            if cat in ssrf_categories:
                security_events.append({
                    "event_type": "input_security_block",
                    "tool": finding.get("tool", "verify_company_website"),
                    "category": cat,
                    "message": finding.get("message", "Target URL blocked by security controls."),
                    "action": "Blocked connection attempt to private, loopback, or metadata address (SSRF protection).",
                    "fraud_risk_points": 0.0,
                })
            elif cat in input_validation_categories:
                field = "contact_email" if cat == "invalid_format" else "company_url"
                input_validation_events.append({
                    "event_type": "input_validation_issue",
                    "tool": finding.get("tool", "unknown"),
                    "field": field,
                    "category": cat,
                    "message": finding.get("message", "Malformed input syntax detected."),
                    "action": "Input rejected by syntax validation; 0 fraud risk points applied.",
                    "fraud_risk_points": 0.0,
                })
            else:
                filtered_tool_findings.append(finding)

        return security_events, input_validation_events, filtered_tool_findings

    @classmethod
    def _map_canonical_evidence(
        cls,
        rule_findings: List[str],
        tool_findings: List[Dict[str, Any]],
        agent_result: Optional[Dict[str, Any]],
        posting_details: Dict[str, Any],
    ) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
        """
        Maps disparate rule triggers and tool findings to unified Canonical Categories.
        Prevents double-counting, enforces context-aware scoring, and produces cautious technical observations.
        """
        canonical_hits: Dict[str, Dict[str, Any]] = {}
        technical_observations: List[str] = []

        tool_cats = {f.get("category"): f for f in tool_findings}
        rule_text = " ".join([str(r).lower() for r in rule_findings])

        # Check for benign fee disclaimer (suppresses false-positive fee findings without subtracting points)
        has_benign_fee_disclaimer = (
            "fee_disclaimer" in tool_cats
            or "zero application fees" in rule_text
            or "never charges any fee" in rule_text
            or "no registration fee" in rule_text
            or "no fees are charged" in rule_text
            or "no fee is required" in rule_text
        )

        def find_rule_match(*keywords: str) -> Optional[str]:
            for r in rule_findings:
                r_low = str(r).lower()
                if any(kw in r_low for kw in keywords):
                    return str(r)
            return None

        # 1. ADVANCE FEE DEMAND
        # Check tool triggers for explicit demands
        fee_tool_hit = False
        fee_messages = []
        for cat in ("registration_fee", "security_deposit", "training_fee", "payment_demand"):
            if cat in tool_cats:
                fee_tool_hit = True
                fee_messages.append(tool_cats[cat]["message"])

        # Check rule screener matches on fee categories
        fee_rule_match = find_rule_match(
            "registration fee",
            "processing fee",
            "security deposit",
            "upfront fee",
            "training fee",
            "background check fee",
        )
        fee_rule_hit = fee_rule_match is not None

        # Check if rules detected an explicit non-registration fee demand (security deposit, training fee, etc.)
        other_fee_rule_matches = [
            r for r in rule_findings
            if any(k in str(r).lower() for k in ("security deposit", "training fee", "background check fee", "upfront fee", "processing fee"))
        ]
        has_other_fee_rule_demand = len(other_fee_rule_matches) > 0

        # Check text for explicit deposit, training, or registration fee demands
        text_lower = (
            str(posting_details.get("description", "")) + " " +
            str(posting_details.get("requirements", "")) + " " +
            str(posting_details.get("stipend", ""))
        ).lower()

        has_explicit_text_fee_demand = any(
            p in text_lower for p in (
                "security deposit", "training fee", "training material fee", "deposit fee",
                "refundable deposit", "non-refundable deposit", "upfront fee",
                "pay registration fee", "registration fee of", "pay fee", "pay deposit"
            )
        ) and not any(
            f"no {p}" in text_lower or f"zero {p}" in text_lower or f"without {p}" in text_lower
            for p in ("security deposit", "training fee", "deposit", "upfront fee")
        )

        # An explicit demand takes priority if:
        # a) Tool confirmed a fee/deposit demand
        # b) Rules confirmed a deposit, training fee, or upfront fee demand
        # c) Text clearly demands a security deposit or training fee
        has_actual_fee_demand = (
            fee_tool_hit
            or has_other_fee_rule_demand
            or has_explicit_text_fee_demand
        )

        # Conflict Resolution:
        # - If posting explicitly demands registration, training, or deposit, the actual demand TAKES PRIORITY!
        # - If there is NO actual demand, a benign fee disclaimer suppresses isolated keyword false positives.
        if has_actual_fee_demand or ((fee_tool_hit or fee_rule_hit) and not has_benign_fee_disclaimer):
            desc = fee_messages[0] if fee_messages else (
                other_fee_rule_matches[0] if other_fee_rule_matches else fee_rule_match
            )
            canonical_hits["advance_fee_demand"] = {
                "category": "advance_fee_demand",
                "raw_points": cls.WEIGHT_ADVANCE_FEE,
                "sources": [s for s, hit in [("Rule Screener", fee_rule_hit or has_other_fee_rule_demand), ("Payment Verifier", fee_tool_hit)] if hit],
                "description": desc or "Mandatory upfront registration fee, training charge, or security deposit requested.",
            }

        # 2. SUSPICIOUS PAYMENT CHANNEL
        channel_tool_hit = "suspicious_payment_channel" in tool_cats
        channel_rule_match = find_rule_match(
            "wire transfer", "western union", "bitcoin", "cryptocurrency", "gift card", "send money"
        )
        channel_rule_hit = channel_rule_match is not None

        if channel_tool_hit or channel_rule_hit:
            desc = (
                tool_cats["suspicious_payment_channel"]["message"]
                if channel_tool_hit
                else channel_rule_match
            )
            canonical_hits["suspicious_payment_channel"] = {
                "category": "suspicious_payment_channel",
                "raw_points": cls.WEIGHT_PAYMENT_CHANNEL,
                "sources": [s for s, hit in [("Rule Screener", channel_rule_hit), ("Payment Verifier", channel_tool_hit)] if hit],
                "description": desc or "Non-standard payment method (cryptocurrency, wire transfer, gift card) detected.",
            }

        # 3. DISPOSABLE EMAIL DOMAIN
        if "disposable_email" in tool_cats:
            canonical_hits["disposable_email_domain"] = {
                "category": "disposable_email_domain",
                "raw_points": cls.WEIGHT_DISPOSABLE_EMAIL,
                "sources": ["Email Verifier"],
                "description": tool_cats["disposable_email"]["message"],
            }

        # 4. CONFIRMED NON-EXISTENT EMAIL DOMAIN (NXDOMAIN only; malformed syntax & timeouts excluded)
        if "domain_not_found" in tool_cats:
            msg = tool_cats["domain_not_found"]["message"]
            if "timeout" not in msg.lower() and "timed out" not in msg.lower():
                canonical_hits["invalid_or_nonexistent_email_domain"] = {
                    "category": "invalid_or_nonexistent_email_domain",
                    "raw_points": cls.WEIGHT_NONEXISTENT_EMAIL,
                    "sources": ["Email Verifier"],
                    "description": "[Email Verifier] Domain does not exist (NXDOMAIN); mail server cannot receive messages.",
                }

        # 5. UNVERIFIED / EXCLUSIVE CHAT RECRUITMENT (Context-aware: exclusive hiring only)
        is_suspicious_chat, chat_desc = cls._evaluate_chat_recruitment(rule_findings, posting_details)
        if is_suspicious_chat:
            canonical_hits["unverified_chat_channel"] = {
                "category": "unverified_chat_channel",
                "raw_points": cls.WEIGHT_UNVERIFIED_CHAT,
                "sources": ["Rule Screener"],
                "description": chat_desc or "Recruitment and interviews conducted exclusively via unverified messaging channels (Telegram/WhatsApp).",
            }

        # 6. UNREALISTIC EARNINGS / GET-RICH-QUICK
        earnings_tool_hit = "unrealistic_earnings" in tool_cats
        earnings_rule_match = find_rule_match("earn money fast", "guaranteed income", "get-rich-quick")
        earnings_rule_hit = earnings_rule_match is not None

        if earnings_tool_hit or earnings_rule_hit:
            desc = (
                tool_cats["unrealistic_earnings"]["message"]
                if earnings_tool_hit
                else earnings_rule_match
            )
            canonical_hits["unrealistic_earnings"] = {
                "category": "unrealistic_earnings",
                "raw_points": cls.WEIGHT_UNREALISTIC_EARNINGS,
                "sources": [s for s, hit in [("Rule Screener", earnings_rule_hit), ("Description Analyzer", earnings_tool_hit)] if hit],
                "description": desc or "Unrealistic earning guarantees or get-rich-quick promises detected.",
            }

        # 7. CONFIRMED DOMAIN FAILURE FOR WEBSITE (Confirmed DNS resolution failure only; malformed URLs & timeouts excluded)
        if "domain_resolution_failure" in tool_cats:
            msg = tool_cats["domain_resolution_failure"]["message"]
            if "timeout" not in msg.lower() and "timed out" not in msg.lower():
                canonical_hits["invalid_website_domain"] = {
                    "category": "invalid_website_domain",
                    "raw_points": cls.WEIGHT_INVALID_WEBSITE,
                    "sources": ["Website Verifier"],
                    "description": "[Website Verifier] Domain resolution failed (hostname has no active DNS records).",
                }

        # 8. EASY SELECTION CLAIMS
        easy_tool_hit = "easy_selection" in tool_cats
        easy_rule_match = find_rule_match("no experience required", "entry barrier")
        easy_rule_hit = easy_rule_match is not None

        if easy_tool_hit or easy_rule_hit:
            desc = (
                tool_cats["easy_selection"]["message"]
                if easy_tool_hit
                else easy_rule_match
            )
            canonical_hits["easy_selection"] = {
                "category": "easy_selection",
                "raw_points": cls.WEIGHT_EASY_SELECTION,
                "sources": [s for s, hit in [("Rule Screener", easy_rule_hit), ("Description Analyzer", easy_tool_hit)] if hit],
                "description": desc or "Immediate selection promises without prerequisite evaluations.",
            }

        # 9. ARTIFICIAL URGENCY TACTICS
        urgency_tool_hit = "urgency_pressure" in tool_cats
        urgency_rule_match = find_rule_match("click here", "urgency", "clickbait")
        urgency_rule_hit = urgency_rule_match is not None

        if urgency_tool_hit or urgency_rule_hit:
            desc = (
                tool_cats["urgency_pressure"]["message"]
                if urgency_tool_hit
                else urgency_rule_match
            )
            canonical_hits["urgency_pressure"] = {
                "category": "urgency_pressure",
                "raw_points": cls.WEIGHT_URGENCY_PRESSURE,
                "sources": [s for s, hit in [("Rule Screener", urgency_rule_hit), ("Description Analyzer", urgency_tool_hit)] if hit],
                "description": desc or "Artificial urgency tactics or countdown pressure applied.",
            }

        # 10. VAGUE ROLE STRUCTURE
        vague_tool_hit = "unclear_requirements" in tool_cats
        vague_rule_match = find_rule_match("must be 18", "work from home", "vague remote work offer", "age-only")
        vague_rule_hit = vague_rule_match is not None

        if vague_tool_hit or vague_rule_hit:
            desc = (
                tool_cats["unclear_requirements"]["message"]
                if vague_tool_hit
                else vague_rule_match
            )
            canonical_hits["vague_role_structure"] = {
                "category": "vague_role_structure",
                "raw_points": cls.WEIGHT_VAGUE_ROLE,
                "sources": [s for s, hit in [("Rule Screener", vague_rule_hit), ("Description Analyzer", vague_tool_hit)] if hit],
                "description": desc or "Vague duties, absent prerequisites, or age-only filtering detected.",
            }

        # Cautious Technical Observations (Award strictly 0.0 negative mitigation points)
        # HTTP 200 Reachability
        if "valid_website" in tool_cats:
            technical_observations.append(
                "Technical signal observed: Company website endpoint is reachable (HTTP 200 response confirmed). Note: Reachability confirms server availability, but does not confirm legal company legitimacy or employer authenticity."
            )

        # Valid MX Records
        if "corporate_email" in tool_cats or "a_record_resolution" in tool_cats:
            if "disposable_email_domain" not in canonical_hits and "invalid_or_nonexistent_email_domain" not in canonical_hits:
                technical_observations.append(
                    "Technical signal observed: Recruiter email domain syntax is valid and active MX records are present. Note: MX records confirm mail delivery capability, not recruiter affiliation or corporate authorization."
                )

        return canonical_hits, technical_observations

    @classmethod
    def _evaluate_chat_recruitment(
        cls, rule_findings: List[str], posting_details: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluates whether Telegram or WhatsApp is used for exclusive/suspicious recruitment
        versus merely being mentioned casually. Casual mentions award 0 risk points.
        """
        text = (
            str(posting_details.get("description", ""))
            + " "
            + str(posting_details.get("requirements", ""))
            + " "
            + str(posting_details.get("title", ""))
            + " "
            + " ".join(str(r) for r in rule_findings)
        ).lower()

        if "telegram" not in text and "whatsapp" not in text:
            return False, None

        # Casual/benign mentions that must remain 0 points
        benign_signals = [
            "telegram bot",
            "whatsapp bot",
            "share on whatsapp",
            "share via whatsapp",
            "follow us on telegram",
            "telegram channel for updates",
            "telegram community",
            "whatsapp group for discussion",
            "community on telegram",
            "telegram group",
            "whatsapp channel",
        ]
        has_benign = any(bs in text for bs in benign_signals)
        has_explicit_hiring = any(
            hs in text
            for hs in (
                "interview on telegram",
                "interview on whatsapp",
                "direct whatsapp interview",
                "unverified telegram contact for hiring",
                "apply via telegram",
                "apply via whatsapp",
                "send cv to whatsapp",
                "send resume to telegram",
                "send resume to whatsapp",
                "contact hr on telegram",
                "contact hr on whatsapp",
            )
        )

        if has_benign and not has_explicit_hiring:
            return False, None

        if has_explicit_hiring:
            for hs in (
                "interview on telegram",
                "interview on whatsapp",
                "direct whatsapp interview",
                "unverified telegram contact for hiring",
                "apply via telegram",
                "apply via whatsapp",
                "send cv to whatsapp",
                "send resume to telegram",
            ):
                if hs in text:
                    return True, f"Recruitment process directs applicants to {hs}."

        for r in rule_findings:
            r_low = str(r).lower()
            if "direct whatsapp interview" in r_low or "unverified telegram contact for hiring" in r_low:
                if any(k in text for k in ("interview", "apply", "contact", "hr", "cv", "resume", "hiring")):
                    return True, str(r)

        return False, None

    @classmethod
    def _compute_scores_and_breakdown(
        cls,
        ml_score: float,
        fake_prob: float,
        canonical_hits: Dict[str, Dict[str, Any]],
    ) -> Tuple[float, Dict[str, Any], int]:
        """
        Computes deterministic score components and builds an exact, transparent breakdown.
        No negative mitigation points are awarded. Breakdown items exactly sum to subtotal_before_clamping.
        """
        has_fee = "advance_fee_demand" in canonical_hits
        has_channel = "suspicious_payment_channel" in canonical_hits

        indicator_items: List[Dict[str, Any]] = []
        evidence_score = 0.0

        if has_fee and has_channel:
            fee_pts = cls.WEIGHT_ADVANCE_FEE
            channel_pts = cls.CAP_FINANCIAL_EXPLOITATION - fee_pts  # 10.0
            canonical_hits["advance_fee_demand"]["points"] = fee_pts
            canonical_hits["suspicious_payment_channel"]["points"] = channel_pts

            indicator_items.append({
                "indicator": "advance_fee_demand",
                "points": fee_pts,
                "sources": canonical_hits["advance_fee_demand"].get("sources", []),
                "explanation": canonical_hits["advance_fee_demand"]["description"],
            })
            indicator_items.append({
                "indicator": "suspicious_payment_channel",
                "points": channel_pts,
                "sources": canonical_hits["suspicious_payment_channel"].get("sources", []),
                "explanation": f"{canonical_hits['suspicious_payment_channel']['description']} (capped within financial exploitation total)",
            })
            evidence_score += cls.CAP_FINANCIAL_EXPLOITATION
        else:
            if has_fee:
                fee_pts = cls.WEIGHT_ADVANCE_FEE
                canonical_hits["advance_fee_demand"]["points"] = fee_pts
                indicator_items.append({
                    "indicator": "advance_fee_demand",
                    "points": fee_pts,
                    "sources": canonical_hits["advance_fee_demand"].get("sources", []),
                    "explanation": canonical_hits["advance_fee_demand"]["description"],
                })
                evidence_score += fee_pts
            elif has_channel:
                chan_pts = cls.WEIGHT_PAYMENT_CHANNEL
                canonical_hits["suspicious_payment_channel"]["points"] = chan_pts
                indicator_items.append({
                    "indicator": "suspicious_payment_channel",
                    "points": chan_pts,
                    "sources": canonical_hits["suspicious_payment_channel"].get("sources", []),
                    "explanation": canonical_hits["suspicious_payment_channel"]["description"],
                })
                evidence_score += chan_pts

        for cat, data in canonical_hits.items():
            if cat not in ("advance_fee_demand", "suspicious_payment_channel"):
                pts = float(data.get("raw_points", 0.0))
                data["points"] = pts
                indicator_items.append({
                    "indicator": cat,
                    "points": pts,
                    "sources": data.get("sources", []),
                    "explanation": data["description"],
                })
                evidence_score += pts

        # Combined evidence contribution cap (combined evidence must not exceed 75.0 points)
        uncapped_evidence_score = evidence_score
        evidence_cap_applied = uncapped_evidence_score > cls.CAP_COMBINED_EVIDENCE
        final_evidence_score = min(cls.CAP_COMBINED_EVIDENCE, uncapped_evidence_score)

        # Subtotal before clamping (no negative mitigation adjustments)
        subtotal_before_clamping = round(ml_score + final_evidence_score, 1)
        final_risk_score = int(round(max(0.0, min(100.0, subtotal_before_clamping))))

        # Calculation summary
        calc_parts = [f"{ml_score:.1f} (ML)"]
        if evidence_cap_applied:
            calc_parts.append(
                f"+ {final_evidence_score:.1f} (Evidence capped at {cls.CAP_COMBINED_EVIDENCE:.0f} pts [uncapped: {uncapped_evidence_score:.1f}])"
            )
        elif final_evidence_score > 0:
            calc_parts.append(f"+ {final_evidence_score:.1f} (Risk Indicators)")
        calc_summary = f"{' '.join(calc_parts)} = {subtotal_before_clamping:.1f} -> Clamped: {final_risk_score}"

        score_breakdown = {
            "ml_contribution": {
                "points": ml_score,
                "fake_probability": fake_prob,
                "max_possible_points": cls.ML_MAX_POINTS,
                "explanation": f"Statistical ML model evaluated posting text and estimated {fake_prob:.1f}% fraud probability, contributing {ml_score:.1f} points.",
            },
            "risk_indicators": indicator_items,
            "evidence_summary": {
                "uncapped_evidence_total": round(uncapped_evidence_score, 1),
                "evidence_cap": cls.CAP_COMBINED_EVIDENCE,
                "evidence_cap_applied": evidence_cap_applied,
                "final_evidence_contribution": round(final_evidence_score, 1),
                "financial_exploitation_capped": has_fee and has_channel,
            },
            "mitigation_adjustments": [],  # Strictly empty; fee disclaimers and technical reachability do not subtract points
            "subtotal_before_clamping": subtotal_before_clamping,
            "final_score": final_risk_score,
            "clamping_applied": final_risk_score != round(subtotal_before_clamping),
            "formula": "final_score = int(round(max(0, min(100, ml_contribution + final_evidence_contribution))))",
            "calculation_summary": calc_summary,
        }

        return final_evidence_score, score_breakdown, final_risk_score

    @classmethod
    def _build_verified_indicators(
        cls,
        technical_observations: List[str],
        posting_details: Dict[str, Any],
        tool_findings: List[Dict[str, Any]],
    ) -> List[str]:
        """
        Builds list of verified technical observations.
        ML predictions are NEVER included here. Fee disclaimers do not claim legitimacy.
        """
        verified: List[str] = list(technical_observations)

        # Check for explicit benign fee disclaimer
        tool_cats = {f.get("category"): f for f in tool_findings}
        desc_text = str(posting_details.get("description", "")).lower()
        if "fee_disclaimer" in tool_cats or "no registration fee" in desc_text or "zero application fees" in desc_text:
            verified.append(
                "Text analysis observed an explicit statement that no application or registration fees are charged. Note: A disclaimer does not constitute verified proof of employer legitimacy."
            )

        return verified

    @classmethod
    def _build_suspicious_indicators(
        cls, canonical_hits: Dict[str, Dict[str, Any]], ml_score: float
    ) -> List[str]:
        """Builds attributed list of confirmed red flag indicators."""
        suspicious: List[str] = []
        for hit in canonical_hits.values():
            sources = ", ".join(hit.get("sources", []))
            prefix = f"[{sources}] " if sources else ""
            suspicious.append(f"{prefix}{hit['description']}")

        if ml_score >= 21.0:  # fake_prob >= 70%
            suspicious.append(
                f"[Machine Learning Model] Textual content strongly resembles fraudulent posting patterns in training data (score contribution: {ml_score}/30 pts)."
            )

        return suspicious

    @classmethod
    def _build_unverified_items(
        cls,
        posting_details: Dict[str, Any],
        agent_result: Optional[Dict[str, Any]],
        tool_unverified: List[str],
        security_events: List[Dict[str, Any]],
        input_validation_events: List[Dict[str, Any]],
    ) -> List[str]:
        """Compiles objective list of missing or unverified fields."""
        unverified: List[str] = list(tool_unverified)

        email = posting_details.get("contact_email") or posting_details.get("email")
        if not email and "Recruiter contact email was not provided in the posting." not in unverified:
            unverified.append("Recruiter contact email was not provided in the posting.")

        url = (
            posting_details.get("company_url")
            or posting_details.get("website")
            or posting_details.get("company_website")
        )
        if not url and "Company website URL was not provided for verification." not in unverified:
            unverified.append("Company website URL was not provided for verification.")

        # Note any input validation issues
        for inp in input_validation_events:
            field_name = inp.get("field", "input")
            unverified.append(
                f"Submitted {field_name} has invalid or malformed syntax and could not be evaluated ({inp.get('message', 'Malformed input')})."
            )

        # Note any security-blocked URLs
        for sec in security_events:
            unverified.append(
                f"Company website endpoint was not evaluated because the submitted URL was blocked by application security filters ({sec.get('action', 'SSRF protection')})."
            )

        if not agent_result:
            unverified.append("Autonomous agent investigation was not performed.")
        elif isinstance(agent_result, dict):
            status = agent_result.get("status")
            if status == "unconfigured":
                unverified.append("Autonomous agent investigation was inactive (Groq API key not configured).")
            elif status == "error":
                err = agent_result.get("error") or "Unknown error"
                unverified.append(f"Autonomous agent investigation was incomplete due to error: {err}")

        # Deduplicate while preserving order
        deduped = []
        seen = set()
        for item in unverified:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped

    @classmethod
    def _build_limitations(
        cls,
        agent_result: Optional[Dict[str, Any]],
        tool_limitations: List[str],
        posting_details: Dict[str, Any],
        security_events: List[Dict[str, Any]],
        input_validation_events: List[Dict[str, Any]],
    ) -> List[str]:
        """Compiles technical and methodological boundaries."""
        limitations: List[str] = list(tool_limitations)

        # Standard foundational boundaries
        limitations.append(
            "ML assessment relies on statistical n-gram patterns and cannot independently verify corporate legal standing."
        )
        limitations.append(
            "Free public email domains (e.g. Gmail) are common among small teams and startups; they do not constitute proof of fraud."
        )
        limitations.append(
            "Network lookups and domain reachability reflect server availability at the time of verification."
        )
        limitations.append(
            "Website reachability (HTTP 200) and DNS records confirm network delivery only, not verified business legitimacy."
        )

        for inp in input_validation_events:
            limitations.append(
                f"Input validation notice: {inp.get('message', 'Malformed syntax')} was flagged during syntax verification; 0 fraud risk points applied."
            )

        for sec in security_events:
            limitations.append(
                f"Application security notice: {sec.get('message', 'Blocked URL')} was safely rejected by SSRF protection filters."
            )

        if not agent_result:
            limitations.append("Agentic multi-tool investigation was not run; scoring relies on heuristics and ML.")
        elif isinstance(agent_result, dict):
            status = agent_result.get("status")
            if status == "unconfigured":
                limitations.append(
                    "Groq API key is not configured; autonomous tool selection and dynamic reasoning were skipped."
                )
            elif status == "error":
                limitations.append(
                    f"Agent execution encountered an operational fault: {agent_result.get('error', 'Unknown')}"
                )

        deduped = []
        seen = set()
        for lim in limitations:
            if lim not in seen:
                seen.add(lim)
                deduped.append(lim)
        return deduped

    @classmethod
    def _generate_recommendations(
        cls,
        risk_level: str,
        canonical_hits: Dict[str, Dict[str, Any]],
        unverified_items: List[str],
        posting_details: Dict[str, Any],
        security_events: List[Dict[str, Any]],
        input_validation_events: List[Dict[str, Any]],
    ) -> List[str]:
        """Generates contextual, practical recommendations based on actual findings."""
        recs: List[str] = []

        # 1. Advance fee / payment recommendations
        if "advance_fee_demand" in canonical_hits:
            recs.append(
                "Never pay upfront registration fees, training charges, or security deposits. Legitimate employers pay interns for work, never the reverse."
            )

        if "suspicious_payment_channel" in canonical_hits:
            recs.append(
                "Do not transact via cryptocurrency, wire transfers, or gift cards; legitimate hiring processes never utilize these irreversible channels."
            )

        # 2. Email / Contact channel recommendations
        if "disposable_email_domain" in canonical_hits or "invalid_or_nonexistent_email_domain" in canonical_hits:
            recs.append(
                "Do not submit resumes containing sensitive personal identity or financial information to unverified or disposable email addresses."
            )

        contact_email = str(
            posting_details.get("contact_email") or posting_details.get("email") or ""
        ).lower()
        if any(dom in contact_email for dom in ("@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com")):
            recs.append(
                "Verify the recruiter's identity through an official company website or corporate switchboard before sharing confidential documents."
            )

        if "unverified_chat_channel" in canonical_hits:
            recs.append(
                "Insist on official corporate communication; treat interviews conducted solely on WhatsApp or Telegram with heightened caution."
            )

        # 3. Web & Corporate Identity recommendations
        if "invalid_website_domain" in canonical_hits:
            recs.append(
                "The provided company URL failed DNS resolution; avoid entering credentials or downloading attachments from unverified domains."
            )

        if any("Company website URL was not provided" in u for u in unverified_items):
            recs.append(
                "Independently search for the company's official careers portal to verify whether this internship is legitimately listed."
            )

        # 4. Role structure recommendations
        if (
            "unrealistic_earnings" in canonical_hits
            or "easy_selection" in canonical_hits
            or "urgency_pressure" in canonical_hits
        ):
            recs.append(
                "Be skeptical of offers guaranteeing high income without prerequisite skills or formal interview evaluations."
            )

        # 5. Baseline recommendations
        if risk_level == "LIKELY LEGITIMATE":
            recs.append(
                "Check whether the internship appears on the company's official careers page or LinkedIn corporate profile before accepting."
            )
            recs.append(
                "Maintain standard privacy practices and withhold bank details until a formal offer letter has been verified."
            )

        if unverified_items:
            recs.append(
                "Treat unverified items as unresolved gaps requiring independent candidate due diligence, not automatic proof of fraud."
            )

        deduped = []
        seen = set()
        for r in recs:
            if r not in seen:
                seen.add(r)
                deduped.append(r)
        return deduped

    @classmethod
    def _compose_summary(
        cls,
        risk_score: int,
        risk_level: str,
        ml_score: float,
        canonical_hits: Dict[str, Dict[str, Any]],
        technical_observations: List[str],
        unverified_items: List[str],
    ) -> str:
        """Composes an explainable, multi-sentence narrative summary justifying the score."""
        if risk_level == "LIKELY LEGITIMATE":
            verdict_desc = "a classification of LIKELY LEGITIMATE (Low Risk Assessment). This reflects low risk indicators based on available signals, not a guarantee of employer authenticity."
        elif risk_level == "SUSPICIOUS":
            verdict_desc = "a classification of SUSPICIOUS. Several risk indicators were detected that warrant independent verification before engaging."
        else:
            verdict_desc = "a classification of HIGH RISK. Critical red flags (such as advance fee demands or untraceable payment channels) were identified."

        parts = [
            f"InternGuard AI evaluated this opportunity and assigned a risk score of {risk_score}/100, resulting in {verdict_desc}"
        ]

        parts.append(
            f"The statistical machine learning model contributed {ml_score:.1f}/30.0 points to the risk score based on lexical text similarity."
        )

        if canonical_hits:
            hit_names = [h.get("description") for h in canonical_hits.values()]
            if len(hit_names) == 1:
                parts.append(f"A key risk indicator was identified: {hit_names[0]}")
            else:
                summary_indicators = "; ".join(hit_names[:3])
                parts.append(f"Primary risk indicators detected include: {summary_indicators}.")
        else:
            parts.append("No high-risk scam keywords or advance-fee patterns were detected in the listing.")

        if technical_observations:
            parts.append(
                "Technical reachability signals were observed, but these do not confirm corporate legal standing."
            )

        if unverified_items:
            parts.append(
                f"{len(unverified_items)} item(s) could not be verified from the submission and require candidate due diligence."
            )

        return " ".join(parts)


def generate_report(
    ml_result: Optional[Dict[str, Any]] = None,
    rule_findings: Optional[List[str]] = None,
    agent_result: Optional[Dict[str, Any]] = None,
    posting_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience functional interface to ReportGenerator.generate_report."""
    return ReportGenerator.generate_report(
        ml_result=ml_result,
        rule_findings=rule_findings,
        agent_result=agent_result,
        posting_details=posting_details,
    )


# Backward-compatible alias
generate_verification_report = generate_report
