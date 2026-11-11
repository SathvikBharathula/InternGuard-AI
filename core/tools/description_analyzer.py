"""
InternGuard AI - Verification Tool 3: Internship Description Analysis
Analyzes internship text for vague responsibilities, exaggerated stipend promises,
unrealistic selection guarantees, low entry barriers, and artificial urgency.
Explains why each finding matters without flagging brevity alone as fraud.
"""

import re
from typing import Dict, Any, List, Optional


# Key indicator regex groups
UNREALISTIC_EARNING_PATTERNS = [
    (r"earn\s+\$?[0-9,]+\s*(?:per|\/)\s*(?:week|day)", "Exaggerated weekly/daily earnings promise"),
    (r"guaranteed\s+income", "Promises of guaranteed high income"),
    (r"earn\s+money\s+fast", "Get-rich-quick framing"),
    (r"make\s+\$?[0-9,]+\s*(?:daily|weekly)", "Unrealistic short-term payout promise"),
    (r"unlimited\s+earning\s+potential", "Unbounded earning claims atypical for internships"),
]

EASY_SELECTION_PATTERNS = [
    (r"no\s+interview\s*(?:needed|required)?", "Bypassing interview/screening process"),
    (r"instant\s+(?:selection|hiring|offer|acceptance)", "Instant selection without technical evaluation"),
    (r"direct\s+(?:selection|joining|hiring)", "Direct hiring without standard vetting"),
    (r"100%\s+(?:selection|placement|job)\s+guarantee", "Guaranteed placement promises"),
    (r"immediate\s+offer\s+letter", "Immediate offer distribution without assessment"),
]

UNCLEAR_REQUIREMENTS_PATTERNS = [
    (r"no\s+skills?\s*(?:needed|required)?", "Zero prerequisite skills requested"),
    (r"no\s+experience\s+(?:needed|required)", "Total lack of experience barrier for technical role"),
    (r"anyone\s+can\s+apply", "Indiscriminate applicant pool without role clarity"),
    (r"no\s+qualifications?\s+(?:needed|required)?", "No educational/academic criteria specified"),
    (r"must\s+be\s+18\s*(?:years|or\s+older)?(?!\s+and)", "Age-only requirement without educational criteria"),
]

URGENCY_PRESSURE_PATTERNS = [
    (r"limited\s+seats?\s+(?:left|available)", "Manufactured scarcity / seat limit"),
    (r"apply\s+immediately", "Urgency pressure to apply rapidly"),
    (r"urgent\s+hiring\s+today", "Extreme hiring urgency"),
    (r"offer\s+expires\s+in\s+\d+\s+(?:hours|minutes)", "High-pressure expiration countdown"),
    (r"click\s+here\s+(?:now|to\s+start)", "Clickbait urgency directives"),
]

# Action verbs typical of legitimate, structured internships
LEGITIMATE_ACTION_VERBS = {
    "develop", "design", "build", "implement", "analyze", "research",
    "test", "collaborate", "assist", "support", "document", "create",
    "maintain", "optimize", "program", "code", "learn", "evaluate",
    "investigate", "contribute", "participate", "troubleshoot", "review"
}


def analyze_internship_description(
    description: Optional[str],
    title: Optional[str] = None,
    requirements: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes internship description, title, and requirements for structural quality,
    plausibility, recruitment red flags, and pressure tactics.

    Args:
        description: Primary body text of the internship posting.
        title: Optional internship title.
        requirements: Optional qualifications/skills text.

    Returns:
        Structured dictionary conforming to the standard tool verification schema.
    """
    result: Dict[str, Any] = {
        "tool": "description_analysis",
        "status": "completed",
        "is_suspicious": False,
        "findings": [],
        "evidence": [],
        "details": {
            "word_count": 0,
            "has_actionable_responsibilities": False,
            "action_verbs_found": [],
            "unrealistic_earnings_detected": False,
            "easy_selection_detected": False,
            "unclear_eligibility_detected": False,
            "urgency_pressure_detected": False,
            "is_brief_description": False,
        },
        "limitations": [],
    }

    full_text = f"{title or ''} {description or ''} {requirements or ''}".strip()

    if not full_text:
        result["status"] = "skipped"
        result["findings"].append({
            "category": "missing_input",
            "severity": "INFO",
            "message": "No text provided for internship description analysis.",
        })
        return result

    desc_text = (description or "").strip()
    words = re.findall(r"\b[a-zA-Z]+\b", desc_text.lower())
    word_count = len(words)
    result["details"]["word_count"] = word_count

    full_text_lower = full_text.lower()

    # 1. Unrealistic Earnings Analysis
    for pattern, label in UNREALISTIC_EARNING_PATTERNS:
        match = re.search(pattern, full_text_lower)
        if match:
            result["is_suspicious"] = True
            result["details"]["unrealistic_earnings_detected"] = True
            result["findings"].append({
                "category": "unrealistic_earnings",
                "severity": "HIGH",
                "message": f"{label}: '{match.group(0)}'.",
                "why_it_matters": (
                    "Authentic internships focus on student mentorship and structured stipends. "
                    "Promises of inflated weekly earnings with minimal effort are typical markers "
                    "of advance-fee fraud, survey harvesting, or illicit money-mule schemes."
                ),
            })
            result["evidence"].append({
                "category": "unrealistic_earnings",
                "snippet": match.group(0),
                "rationale": label,
            })

    # 2. Suspiciously Easy Selection Claims
    for pattern, label in EASY_SELECTION_PATTERNS:
        match = re.search(pattern, full_text_lower)
        if match:
            result["is_suspicious"] = True
            result["details"]["easy_selection_detected"] = True
            result["findings"].append({
                "category": "easy_selection",
                "severity": "HIGH",
                "message": f"{label}: '{match.group(0)}'.",
                "why_it_matters": (
                    "Legitimate organizations vet interns through interviews, skill checks, or academic records. "
                    "Promising instant selection without vetting is designed to bypass critical thinking "
                    "and funnel applicants directly into fee-paying steps."
                ),
            })
            result["evidence"].append({
                "category": "easy_selection",
                "snippet": match.group(0),
                "rationale": label,
            })

    # 3. Unclear / Indiscriminate Eligibility Requirements
    for pattern, label in UNCLEAR_REQUIREMENTS_PATTERNS:
        match = re.search(pattern, full_text_lower)
        if match:
            result["is_suspicious"] = True
            result["details"]["unclear_eligibility_detected"] = True
            result["findings"].append({
                "category": "unclear_eligibility",
                "severity": "MEDIUM",
                "message": f"{label}: '{match.group(0)}'.",
                "why_it_matters": (
                    "Internships are intended to build on academic foundations. Stating 'no skills or experience' "
                    "for professional or technical titles often conceals repetitive click-work, data harvesting, or unpaid sales tasks."
                ),
            })
            result["evidence"].append({
                "category": "unclear_eligibility",
                "snippet": match.group(0),
                "rationale": label,
            })

    # 4. Urgency & Pressure Tactics
    for pattern, label in URGENCY_PRESSURE_PATTERNS:
        match = re.search(pattern, full_text_lower)
        if match:
            result["is_suspicious"] = True
            result["details"]["urgency_pressure_detected"] = True
            result["findings"].append({
                "category": "urgency_pressure",
                "severity": "MEDIUM",
                "message": f"{label}: '{match.group(0)}'.",
                "why_it_matters": (
                    "Scammers create artificial deadlines ('limited seats', 'apply now') to force students "
                    "into acting impulsively before they can verify employer credentials or consult university career cells."
                ),
            })
            result["evidence"].append({
                "category": "urgency_pressure",
                "snippet": match.group(0),
                "rationale": label,
            })

    # 5. Operational Responsibility & Brevity Evaluation
    found_verbs = [v for v in LEGITIMATE_ACTION_VERBS if v in words]
    result["details"]["action_verbs_found"] = found_verbs
    result["details"]["has_actionable_responsibilities"] = len(found_verbs) >= 2

    # Brevity check (INFO only, NEVER classified as fraud solely for being short)
    if word_count < 30 and word_count > 0:
        result["details"]["is_brief_description"] = True
        result["findings"].append({
            "category": "brevity_observation",
            "severity": "INFO",
            "message": f"Posting description is concise ({word_count} words).",
            "why_it_matters": (
                "While brevity alone does not indicate fraud, concise listings provide limited operational detail. "
                "Students should ensure full role scopes and expectations are clarified before accepting."
            ),
        })

    # Vague responsibilities check (sufficient length but lacks concrete duties)
    if word_count >= 30 and len(found_verbs) < 2:
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "vague_responsibilities",
            "severity": "MEDIUM",
            "message": "Description lacks concrete technical or operational responsibility verbs.",
            "why_it_matters": (
                "Legitimate internships describe daily learning tasks and responsibilities (e.g. design, analyze, test). "
                "Postings with vague duty descriptions frequently mask marketing spam or administrative filler."
            ),
        })

    return result
