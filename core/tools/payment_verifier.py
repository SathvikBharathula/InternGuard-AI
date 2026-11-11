"""
InternGuard AI - Verification Tool 2: Payment Request Detection
Detects upfront registration fees, security deposits, training charges,
and suspicious payment methods, while distinguishing explicit payment demands
from benign/negated fee mentions.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


# Categories of payment fraud patterns
PAYMENT_PATTERNS = {
    "registration_fee": [
        r"registration\s+fee[s]?",
        r"application\s+fee[s]?",
        r"processing\s+fee[s]?",
        r"enrollment\s+fee[s]?",
        r"portal\s+charge[s]?",
        r"entry\s+fee[s]?",
    ],
    "security_deposit": [
        r"security\s+deposit[s]?",
        r"refundable\s+deposit[s]?",
        r"caution\s+deposit[s]?",
        r"equipment\s+deposit[s]?",
        r"laptop\s+deposit[s]?",
    ],
    "training_fee": [
        r"training\s+fee[s]?",
        r"training\s+cost[s]?",
        r"training\s+material[s]?\s+fee",
        r"starter\s+kit\s+fee",
        r"certification\s+fee[s]?",
        r"onboarding\s+fee[s]?",
        r"background\s+check\s+fee[s]?",
    ],
    "payment_to_secure": [
        r"pay\s+to\s+(?:start|work|apply|secure|join)",
        r"upfront\s+fee[s]?",
        r"upfront\s+payment[s]?",
        r"fee\s+(?:required|applies|to\s+confirm)",
        r"deposit\s+(?:required|to\s+secure)",
        r"send\s+(?:\$?\d+|money)\s+(?:for|to|before)",
    ],
    "suspicious_payment_methods": [
        r"western\s+union",
        r"wire\s+transfer",
        r"moneygram",
        r"bitcoin",
        r"cryptocurrency",
        r"crypto\s+transfer",
        r"gift\s+card[s]?",
        r"cash\s+app",
        r"zelle(?:\s+transfer)?",
        r"cash\s+(?:a\s+)?check",
    ],
}

# Negation and benign disclaimer phrases
NEGATION_PATTERNS = [
    r"no\s+(?:application|registration|training|upfront|hidden)?\s*fee[s]?",
    r"never\s+(?:ask|charge|require|demand)(?:\s+(?:for|any))?\s*(?:fees?|money|payment|deposits?)?",
    r"zero\s+(?:application|registration|training|upfront)?\s*(?:cost|fee[s]?|charges)",
    r"without\s+any\s+(?:fee[s]?|cost|charge|deposit)",
    r"free\s+of\s+cost",
    r"100%\s+free",
    r"covered\s+by\s+(?:the\s+)?(?:us|company|employer)",
    r"we\s+do\s+not\s+(?:charge|require)",
    r"no\s+deposit",
    r"no\s+hidden\s+cost",
    r"free\s+training",
]


def verify_payment_requests(
    text: Optional[str],
    stipend: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scans internship text and stipend fields for advance-fee requests,
    unusual payment methods, and deposit demands.

    Args:
        text: Internship description, requirements, or offer letter body.
        stipend: Optional stipend/compensation string.

    Returns:
        Structured dictionary conforming to the standard tool verification schema.
    """
    result: Dict[str, Any] = {
        "tool": "payment_verification",
        "status": "completed",
        "is_suspicious": False,
        "findings": [],
        "evidence": [],
        "details": {
            "explicit_demands_count": 0,
            "suspicious_methods_count": 0,
            "negated_mentions_count": 0,
            "categories_triggered": [],
        },
        "limitations": [],
    }

    combined_text = f"{text or ''} {stipend or ''}".strip()

    if not combined_text:
        result["status"] = "skipped"
        result["findings"].append({
            "category": "missing_input",
            "severity": "INFO",
            "message": "No text provided for payment verification.",
        })
        return result

    # Break into sentences for context-aware extraction
    sentences = _split_into_sentences(combined_text)

    categories_found = set()
    explicit_count = 0
    methods_count = 0
    negated_count = 0

    for sentence in sentences:
        sentence_clean = sentence.strip()
        sentence_lower = sentence_clean.lower()

        # Check for negation in this sentence
        neg_match = next((re.search(neg, sentence_lower) for neg in NEGATION_PATTERNS if re.search(neg, sentence_lower)), None)
        is_negated = (neg_match is not None)

        if is_negated:
            negated_count += 1
            result["findings"].append({
                "category": "safe_fee_policy",
                "severity": "INFO",
                "message": f"Payment/fee term mentioned in benign/negated context ('{neg_match.group(0)}').",
            })
            result["evidence"].append({
                "type": "benign_disclaimer",
                "matched_term": neg_match.group(0),
                "snippet": sentence_clean,
                "is_negated": True,
            })

        # Evaluate against each payment pattern
        for category, regex_list in PAYMENT_PATTERNS.items():
            for regex in regex_list:
                match = re.search(regex, sentence_lower)
                if match:
                    snippet = sentence_clean
                    matched_term = match.group(0)

                    # If sentence is negated and category is a fee/deposit, do NOT flag as scam!
                    if is_negated and category != "suspicious_payment_methods":
                        continue

                    # Explicit payment demand or suspicious method
                    categories_found.add(category)
                    result["is_suspicious"] = True

                    if category == "suspicious_payment_methods":
                        methods_count += 1
                        severity = "HIGH"
                        desc = f"Suspicious payment or money-transfer instruction detected: '{matched_term}'."
                    elif category == "security_deposit":
                        explicit_count += 1
                        severity = "HIGH"
                        desc = f"Security deposit or caution fee demanded: '{matched_term}'."
                    elif category == "registration_fee":
                        explicit_count += 1
                        severity = "HIGH"
                        desc = f"Registration or application fee demand detected: '{matched_term}'."
                    elif category == "training_fee":
                        explicit_count += 1
                        severity = "HIGH"
                        desc = f"Mandatory fee for training, certification or materials detected: '{matched_term}'."
                    else:
                        explicit_count += 1
                        severity = "HIGH"
                        desc = f"Advance payment demand to secure internship: '{matched_term}'."

                    result["findings"].append({
                        "category": category,
                        "severity": severity,
                        "message": desc,
                    })
                    result["evidence"].append({
                        "type": "payment_demand",
                        "matched_term": matched_term,
                        "snippet": snippet,
                        "is_negated": False,
                    })

    # Summary details
    result["details"]["explicit_demands_count"] = explicit_count
    result["details"]["suspicious_methods_count"] = methods_count
    result["details"]["negated_mentions_count"] = negated_count
    result["details"]["categories_triggered"] = sorted(list(categories_found))

    return result


def _split_into_sentences(text: str) -> List[str]:
    """Splits body text into sentences or clause units."""
    chunks = re.split(r"(?<=[.!?;\n])\s+", text)
    return [c.strip() for c in chunks if c.strip()]
