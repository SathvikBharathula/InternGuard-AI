"""
InternGuard AI - Verification Tool 1: Email Verification
Validates recruiter and contact email addresses, checks DNS/MX deliverability,
and identifies public/disposable email providers without treating public webmail
alone as proof of fraud.
"""

import re
import socket
from typing import Dict, Any, List, Optional

# Optional dnspython for MX resolution
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# Known free/public webmail providers
PUBLIC_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    "zoho.com",
    "mail.com",
    "gmx.com",
    "gmx.net",
    "yandex.com",
}

# Known disposable/temporary email domains
DISPOSABLE_EMAIL_DOMAINS = {
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "guerrillamailblock.com",
    "mailinator.com",
    "sharklasers.com",
    "throwawaymail.com",
    "yopmail.com",
    "trashmail.com",
    "getairmail.com",
    "dispostable.com",
    "fakeinbox.com",
    "temp-mail.org",
    "burnermail.io",
}

# Standard email syntax pattern
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$"
)


def verify_email(email: Optional[str], check_dns: bool = True) -> Dict[str, Any]:
    """
    Validates a contact email address for internship postings.

    Args:
        email: Contact or recruiter email string.
        check_dns: Whether to perform live DNS/MX resolution (can be disabled for unit tests).

    Returns:
        Structured dictionary conforming to the standard tool verification schema.
    """
    result: Dict[str, Any] = {
        "tool": "email_verification",
        "status": "completed",
        "is_suspicious": False,
        "findings": [],
        "evidence": [],
        "details": {
            "email": email or "",
            "domain": None,
            "is_valid_format": False,
            "is_public_provider": False,
            "is_disposable": False,
            "domain_resolves": False,
            "has_mx_records": False,
            "mx_records": [],
        },
        "limitations": [],
    }

    if not email or not isinstance(email, str) or not email.strip():
        result["status"] = "skipped"
        result["findings"].append({
            "category": "missing_input",
            "severity": "INFO",
            "message": "No contact email provided for verification.",
        })
        return result

    cleaned_email = email.strip()
    result["details"]["email"] = cleaned_email

    # 1. Format validation
    match = EMAIL_REGEX.match(cleaned_email)
    if not match:
        result["is_suspicious"] = True
        result["details"]["is_valid_format"] = False
        result["findings"].append({
            "category": "invalid_format",
            "severity": "HIGH",
            "message": f"Malformed email syntax: '{cleaned_email}' does not conform to standard RFC email format.",
        })
        result["evidence"].append({
            "field": "contact_email",
            "snippet": cleaned_email,
            "reason": "Failed regex pattern validation",
        })
        return result

    result["details"]["is_valid_format"] = True
    domain = match.group(1).lower()
    result["details"]["domain"] = domain

    # Additional check: consecutive dots or invalid TLD
    if ".." in domain or not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        result["is_suspicious"] = True
        result["details"]["is_valid_format"] = False
        result["findings"].append({
            "category": "invalid_domain",
            "severity": "HIGH",
            "message": f"Invalid domain structure: '{domain}'.",
        })
        return result

    # 2. Check for disposable / throwaway email service
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        result["is_suspicious"] = True
        result["details"]["is_disposable"] = True
        result["findings"].append({
            "category": "disposable_email",
            "severity": "HIGH",
            "message": f"Domain '{domain}' is a known temporary/disposable email service commonly associated with fraudulent campaigns.",
        })
        result["evidence"].append({
            "field": "contact_email",
            "snippet": cleaned_email,
            "reason": "Matches known disposable email registry",
        })

    # 3. Check for generic / public webmail provider
    elif domain in PUBLIC_EMAIL_DOMAINS:
        result["details"]["is_public_provider"] = True
        # NOTE: Identified as an observation (INFO), NEVER proof of fraud alone
        result["findings"].append({
            "category": "public_webmail",
            "severity": "INFO",
            "message": f"Uses public webmail provider (@{domain}). While common for student startups or early founders, established companies generally use branded domain emails.",
        })
        result["evidence"].append({
            "field": "contact_email",
            "snippet": cleaned_email,
            "reason": "Public webmail provider identified (informational)",
        })

    # 4. Check DNS & MX resolution
    if check_dns:
        _perform_dns_resolution(domain, result)
    else:
        result["limitations"].append("Live DNS resolution was skipped by configuration.")

    return result


def _perform_dns_resolution(domain: str, result: Dict[str, Any]) -> None:
    """Helper to query DNS and MX records safely."""
    # Attempt MX lookup with dnspython if installed
    if DNS_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 2.5
            resolver.timeout = 2.5
            mx_answers = resolver.resolve(domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]

            result["details"]["domain_resolves"] = True
            result["details"]["has_mx_records"] = True
            result["details"]["mx_records"] = mx_hosts[:5]

            result["findings"].append({
                "category": "mx_resolution",
                "severity": "INFO",
                "message": f"Domain '{domain}' successfully resolved with {len(mx_hosts)} active mail exchanger(s).",
            })
            return

        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # No MX records, try falling back to A record
            pass
        except dns.resolver.NXDOMAIN:
            result["is_suspicious"] = True
            result["details"]["domain_resolves"] = False
            result["details"]["has_mx_records"] = False
            result["findings"].append({
                "category": "domain_not_found",
                "severity": "HIGH",
                "message": f"Domain '{domain}' does not exist (NXDOMAIN). Emails to this address cannot be received.",
            })
            result["evidence"].append({
                "field": "contact_email",
                "snippet": domain,
                "reason": "NXDOMAIN: Domain has no DNS registration",
            })
            return
        except dns.exception.Timeout:
            result["limitations"].append(f"DNS lookup for '{domain}' timed out after 2.5s.")
        except Exception as exc:
            result["limitations"].append(f"DNS lookup encounter: {type(exc).__name__}.")

    # Fallback / Secondary resolution via standard library socket
    try:
        addr_info = socket.getaddrinfo(domain, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_info:
            result["details"]["domain_resolves"] = True
            if not result["details"]["has_mx_records"]:
                result["findings"].append({
                    "category": "a_record_resolution",
                    "severity": "INFO",
                    "message": f"Domain '{domain}' has valid host address records, though no direct MX records were confirmed.",
                })
        else:
            result["is_suspicious"] = True
            result["details"]["domain_resolves"] = False
            result["findings"].append({
                "category": "domain_not_found",
                "severity": "HIGH",
                "message": f"Domain '{domain}' failed to resolve to any IP address.",
            })
    except socket.gaierror:
        result["is_suspicious"] = True
        result["details"]["domain_resolves"] = False
        result["findings"].append({
            "category": "domain_not_found",
            "severity": "HIGH",
            "message": f"Domain '{domain}' could not be resolved (DNS gaierror). Likely non-existent or inactive.",
        })
    except Exception as exc:
        result["limitations"].append(f"Standard socket DNS check encounter: {type(exc).__name__}.")
