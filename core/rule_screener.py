"""
InternGuard AI - Rule-Based Screener Module
Scans job and internship postings for known fraud patterns, scam keywords,
and advance-fee indicators for explainability.
"""

from typing import List, Dict, Optional


class RuleScreener:
    """
    Transparent, deterministic heuristic layer that scans job text and metadata
    for high-risk fraud keywords and suspicious internship signals.
    """

    # Baseline 13 heuristic indicators from original application
    BASE_HEURISTICS: Dict[str, str] = {
        "work from home": "Suspiciously vague remote work offer",
        "no experience required": "Unrealistic entry barrier",
        "earn money fast": "Get-rich-quick language detected",
        "guaranteed income": "Guaranteed income promises are a red flag",
        "send money": "Requesting money transfer — major scam indicator",
        "wire transfer": "Wire transfer requests are scam indicators",
        "western union": "Western Union payment — common fraud pattern",
        "bitcoin": "Cryptocurrency payment — common fraud pattern",
        "upfront fee": "Upfront fee requests are a red flag",
        "training fee": "Training fee requests are suspicious",
        "background check fee": "Legitimate employers never charge background check fees",
        "must be 18": "Age-only requirement suggests lack of role clarity",
        "click here": "Urgency/clickbait language detected",
    }

    # Additional internship-specific heuristic patterns
    INTERNSHIP_HEURISTICS: Dict[str, str] = {
        "registration fee": "Internships charging a registration fee are typically fraudulent",
        "processing fee": "Application or processing fees are prohibited for legitimate internships",
        "security deposit": "Asking for a refundable/non-refundable security deposit is a scam indicator",
        "telegram": "Unverified Telegram contact for hiring and interview process",
        "whatsapp": "Direct WhatsApp interview without official domain communication",
        "gift card": "Gift card purchases as work tasks are a classic money-mule scam",
    }

    def __init__(self, include_internship_heuristics: bool = True):
        self.heuristics = dict(self.BASE_HEURISTICS)
        if include_internship_heuristics:
            self.heuristics.update(self.INTERNSHIP_HEURISTICS)

    def screen(
        self,
        text: str,
        contact_email: Optional[str] = None,
        stipend: Optional[str] = None,
        **kwargs
    ) -> List[str]:
        """
        Screens text and optional metadata against known scam patterns.
        Returns a deduplicated list of human-readable red flag messages.
        """
        red_flags: List[str] = []
        text_lower = (text or "").lower()

        for kw, msg in self.heuristics.items():
            if kw in text_lower:
                red_flags.append(msg)

        # Check contact email if provided
        if contact_email:
            email_lower = contact_email.strip().lower()
            free_domains = ("@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com")
            if any(email_lower.endswith(dom) for dom in free_domains):
                red_flags.append(
                    "Free public email domain used for recruiter contact instead of corporate domain"
                )

        # Check stipend field if provided
        if stipend:
            stipend_lower = stipend.strip().lower()
            for kw in ("guaranteed", "unlimited", "upfront fee", "commission only"):
                if kw in stipend_lower and self.heuristics.get(kw) not in red_flags:
                    red_flags.append(f"Suspicious compensation term: '{kw}' detected")

        # Deduplicate while preserving insertion order
        seen = set()
        deduped = []
        for flag in red_flags:
            if flag not in seen:
                seen.add(flag)
                deduped.append(flag)

        return deduped
