"""
InternGuard AI - Verification Tool 4: Company Website Verification
Validates company website URLs, prevents SSRF attacks, checks reachability,
and inspects public metadata without treating the existence of a website or HTTPS
as proof of corporate legitimacy.
"""

import re
import socket
import ipaddress
import http.client
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple


# Maximum bytes to download (prevents memory exhaustion or file download attacks)
MAX_RESPONSE_BYTES = 65536  # 64 KB
MAX_REDIRECTS = 3
REQUEST_TIMEOUT_SECONDS = 3.0

# Known localhost strings and cloud metadata endpoints
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


def verify_company_website(
    url: Optional[str],
    check_reachability: bool = True
) -> Dict[str, Any]:
    """
    Validates a company website URL with strict SSRF defense.

    Args:
        url: Target company website URL string.
        check_reachability: Whether to perform network resolution and safe GET request.

    Returns:
        Structured dictionary conforming to the standard tool verification schema.
    """
    result: Dict[str, Any] = {
        "tool": "website_verification",
        "status": "completed",
        "is_suspicious": False,
        "findings": [],
        "evidence": [],
        "details": {
            "input_url": url or "",
            "normalized_url": None,
            "scheme": None,
            "hostname": None,
            "port": None,
            "is_valid_url": False,
            "resolved_ips": [],
            "is_reachable": False,
            "http_status": None,
            "is_https": False,
            "page_title": None,
            "redirect_history": [],
            "ssrf_safe": False,
        },
        "limitations": [
            "Website availability and HTTPS encryption verify domain hosting status only, never legal corporate legitimacy.",
            "DNS resolution occurs prior to connection; theoretical DNS rebinding cannot be eliminated without custom OS socket pinning.",
        ],
    }

    if not url or not isinstance(url, str) or not url.strip():
        result["status"] = "skipped"
        result["findings"].append({
            "category": "missing_input",
            "severity": "INFO",
            "message": "No company website URL provided for verification.",
        })
        return result

    raw_url = url.strip()
    result["details"]["input_url"] = raw_url

    # 1. Scheme normalization and validation
    # If user provided 'company.com' without scheme, normalize to https://
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw_url):
        candidate_url = f"https://{raw_url}"
    else:
        candidate_url = raw_url

    try:
        parsed = urllib.parse.urlsplit(candidate_url)
    except Exception as exc:
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "malformed_url",
            "severity": "HIGH",
            "message": f"Malformed URL structure: {exc}",
        })
        return result

    scheme = parsed.scheme.lower()
    result["details"]["scheme"] = scheme

    # Strict Scheme Restriction: only http and https allowed
    if scheme not in ("http", "https"):
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "forbidden_scheme",
            "severity": "HIGH",
            "message": f"Forbidden URL scheme '{scheme}'. Only HTTP and HTTPS protocols are permitted.",
        })
        result["evidence"].append({
            "field": "company_url",
            "snippet": candidate_url,
            "reason": f"Disallowed scheme: '{scheme}'",
        })
        return result

    hostname = (parsed.hostname or "").lower()

    # Safely extract port without raising on malformed port strings
    try:
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
    except (ValueError, TypeError):
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "malformed_url",
            "severity": "HIGH",
            "message": "Invalid URL port specification.",
        })
        return result

    result["details"]["hostname"] = hostname
    result["details"]["port"] = port

    # SSRF guard for loopback / localhost before dot check
    if hostname in BLOCKED_HOSTNAMES:
        result["is_suspicious"] = True
        result["details"]["ssrf_safe"] = False
        result["findings"].append({
            "category": "ssrf_security_block",
            "severity": "HIGH",
            "message": f"SSRF Security Violation: Host '{hostname}' is a reserved loopback or internal address.",
        })
        return result

    if not hostname or "." not in hostname:
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "invalid_hostname",
            "severity": "HIGH",
            "message": f"Invalid hostname '{hostname}'. Expected a qualified domain name.",
        })
        return result

    result["details"]["is_valid_url"] = True
    result["details"]["normalized_url"] = candidate_url
    result["details"]["is_https"] = (scheme == "https")

    if not check_reachability:
        result["limitations"].append("Live network reachability check skipped by configuration.")
        return result

    # 2. SSRF Protection: Hostname and DNS resolution validation
    ssrf_safe, ssrf_reason, resolved_ips = _validate_ssrf_safety(hostname, port)
    result["details"]["resolved_ips"] = resolved_ips
    result["details"]["ssrf_safe"] = ssrf_safe

    if not ssrf_safe:
        result["is_suspicious"] = True
        result["findings"].append({
            "category": "ssrf_security_block",
            "severity": "HIGH",
            "message": f"SSRF Security Violation: {ssrf_reason}",
        })
        result["evidence"].append({
            "field": "company_url",
            "snippet": f"{hostname} -> {resolved_ips}",
            "reason": ssrf_reason,
        })
        return result

    # 3. Perform safe, controlled HTTP retrieval with redirect validation
    _execute_safe_http_request(candidate_url, result)

    return result


def _validate_ssrf_safety(hostname: str, port: int) -> Tuple[bool, str, List[str]]:
    """
    Validates that a hostname does not point to localhost, private networks,
    link-local addresses (e.g. cloud metadata 169.254.169.254), or non-public IPs.
    """
    # 1. String blacklist check
    if hostname in BLOCKED_HOSTNAMES:
        return False, f"Host '{hostname}' is a reserved internal or localhost address.", []

    # 2. Resolve DNS addresses
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            ip_str = entry[4][0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as exc:
        return False, f"Domain '{hostname}' could not be resolved (DNS failure: {exc}).", []
    except Exception as exc:
        return False, f"DNS resolution error for '{hostname}': {exc}.", []

    if not resolved_ips:
        return False, f"Domain '{hostname}' resolved to zero IP addresses.", []

    # 3. Evaluate each resolved IP address
    for ip_str in resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str)

            if ip.is_loopback:
                return False, f"Resolved IP {ip_str} is a loopback address (127.0.0.0/8 or ::1).", resolved_ips
            if ip.is_private:
                return False, f"Resolved IP {ip_str} belongs to a private/internal network (RFC 1918).", resolved_ips
            if ip.is_link_local:
                return False, f"Resolved IP {ip_str} is a link-local address (e.g. cloud metadata endpoint).", resolved_ips
            if ip.is_reserved:
                return False, f"Resolved IP {ip_str} is an IETF reserved address.", resolved_ips
            if ip.is_multicast:
                return False, f"Resolved IP {ip_str} is a multicast address.", resolved_ips
            if ip.is_unspecified:
                return False, f"Resolved IP {ip_str} is an unspecified address (0.0.0.0 or ::).", resolved_ips

            # Explicit guard against 169.254.169.254 (AWS, GCP, Azure metadata)
            if ip_str == "169.254.169.254":
                return False, "Access to cloud metadata IP (169.254.169.254) is strictly prohibited.", resolved_ips

        except ValueError:
            return False, f"Invalid IP address format encountered: '{ip_str}'.", resolved_ips

    return True, "Public IP confirmed", resolved_ips


def _execute_safe_http_request(start_url: str, result: Dict[str, Any]) -> None:
    """
    Executes a single or multi-step redirect HTTP request using http.client,
    re-validating every redirect destination for SSRF safety.
    """
    current_url = start_url
    redirects_followed = 0

    while redirects_followed <= MAX_REDIRECTS:
        parsed = urllib.parse.urlsplit(current_url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Re-validate destination if this was a redirect
        if redirects_followed > 0:
            result["details"]["redirect_history"].append(current_url)
            safe, reason, ips = _validate_ssrf_safety(hostname, port)
            if not safe:
                result["is_suspicious"] = True
                result["findings"].append({
                    "category": "redirect_ssrf_block",
                    "severity": "HIGH",
                    "message": f"Redirect to unsafe destination blocked: {reason}",
                })
                return

        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(hostname, port=port, timeout=REQUEST_TIMEOUT_SECONDS)
            else:
                conn = http.client.HTTPConnection(hostname, port=port, timeout=REQUEST_TIMEOUT_SECONDS)

            headers = {
                "User-Agent": "InternGuard-AI-Verifier/1.0",
                "Accept": "text/html,text/plain",
                "Connection": "close",
            }
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()

            status = response.status
            result["details"]["http_status"] = status

            # Handle redirects manually
            if status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    break
                # Resolve relative redirect URLs
                current_url = urllib.parse.urljoin(current_url, location)
                redirects_followed += 1
                continue

            # Read bounded payload
            result["details"]["is_reachable"] = (status < 400)
            body_bytes = response.read(MAX_RESPONSE_BYTES)

            content_type = response.getheader("Content-Type", "")
            if "text/html" in content_type.lower() or not content_type:
                # Extract page title
                body_text = body_bytes.decode("utf-8", errors="ignore")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    clean_title = re.sub(r"\s+", " ", title_match.group(1)).strip()
                    result["details"]["page_title"] = clean_title[:100]

            # Assess status findings
            if status < 400:
                proto_text = "HTTPS (encrypted)" if scheme == "https" else "unencrypted HTTP"
                result["findings"].append({
                    "category": "website_reachable",
                    "severity": "INFO",
                    "message": f"Website is active (HTTP {status}) using {proto_text}.",
                })
                if scheme != "https":
                    result["findings"].append({
                        "category": "unencrypted_website",
                        "severity": "MEDIUM",
                        "message": "Company website uses unencrypted HTTP rather than modern HTTPS.",
                    })
            elif status == 404:
                result["is_suspicious"] = True
                result["findings"].append({
                    "category": "website_not_found",
                    "severity": "HIGH",
                    "message": f"Website returned HTTP 404 Not Found at '{current_url}'.",
                })
            else:
                result["findings"].append({
                    "category": "website_http_error",
                    "severity": "MEDIUM",
                    "message": f"Website returned non-success HTTP status {status}.",
                })

            break

        except socket.timeout:
            result["findings"].append({
                "category": "connection_timeout",
                "severity": "MEDIUM",
                "message": f"Connection to '{hostname}' timed out after {REQUEST_TIMEOUT_SECONDS}s.",
            })
            result["limitations"].append("Network timeout during website request.")
            break
        except Exception as exc:
            result["findings"].append({
                "category": "connection_error",
                "severity": "MEDIUM",
                "message": f"Could not establish connection to '{hostname}': {exc}.",
            })
            break
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
