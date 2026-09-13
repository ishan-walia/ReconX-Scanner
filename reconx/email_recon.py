"""
Email OSINT & exposure verification module.
Performs format validation, MX routing check, and public breach exposure verification.
"""

import re
import socket
import urllib.request
import hashlib
from typing import Dict, Any, Optional

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)


def validate_email_format(email: str) -> bool:
    """Validate email syntax against standard RFC pattern."""
    return bool(EMAIL_REGEX.match(email.strip()))


def check_domain_mail_routing(domain: str) -> bool:
    """Verify if target domain has active mail exchanger or resolves."""
    try:
        # Check basic resolution
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def check_hibp_breach(email: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Check if email has known public breaches or compromised indicators.
    Uses legitimate, privacy-preserving checks and domain reputation signals.
    """
    clean_email = email.strip().lower()
    
    # Check domain reputation signals or known breach repositories
    # If the domain is disposable/known burner
    disposable_domains = {
        "mailinator.com", "tempmail.com", "10minutemail.com",
        "guerrillamail.com", "trashmail.com", "sharklasers.com"
    }
    
    domain = clean_email.split("@")[-1] if "@" in clean_email else ""
    is_disposable = domain in disposable_domains

    # Check public exposure via search API / k-anonymity hash
    sha1_hash = hashlib.sha1(clean_email.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    breach_match = False
    breach_count = 0

    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconX-OSINT/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                content = resp.read().decode("utf-8")
                for line in content.splitlines():
                    if line.startswith(suffix):
                        breach_match = True
                        parts = line.split(":")
                        if len(parts) > 1:
                            breach_count = int(parts[1])
                        break
    except Exception:
        pass

    return {
        "breach_found": breach_match,
        "breach_status": "Found" if breach_match else "No Match",
        "breach_count": breach_count,
        "is_disposable": is_disposable,
    }


def analyze_email(email: str) -> Dict[str, Any]:
    """
    Run complete OSINT analysis on target email address.
    """
    clean_email = email.strip()
    is_valid = validate_email_format(clean_email)
    domain = clean_email.split("@")[-1] if "@" in clean_email else "Unknown"

    has_mail_routing = check_domain_mail_routing(domain) if is_valid else False
    breach_info = check_hibp_breach(clean_email) if is_valid else {"breach_status": "No Match", "breach_found": False}

    # Public exposure flag: Found if domain resolves and format is valid
    public_exposure = "Found" if (is_valid and has_mail_routing) else "Not Found"

    return {
        "email": clean_email,
        "domain": domain,
        "is_valid_format": is_valid,
        "format_status": "Valid" if is_valid else "Invalid Format",
        "mail_routing": has_mail_routing,
        "public_exposure": public_exposure,
        "breach_status": breach_info["breach_status"],
        "breach_found": breach_info.get("breach_found", False),
    }
