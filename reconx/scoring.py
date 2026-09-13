"""
Exposure & Risk Scoring Engine for ReconX.
Computes an aggregate Exposure Score (0-100), Level (LOW, MEDIUM, HIGH),
and generates remediation recommendations.
"""

from typing import Dict, Any, List, Tuple


def calculate_exposure_score(
    domain_data: Dict[str, Any],
    website_data: Dict[str, Any],
    subdomain_data: List[str],
    email_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluate overall surface exposure and security posture.
    
    Levels:
      0  - 30 : LOW
      31 - 60 : MEDIUM
      61 - 100: HIGH
    """
    score = 0
    findings: List[str] = []
    recommendations: List[str] = []

    # 1. SSL & HTTPS Assessment
    ssl_info = website_data.get("ssl", {})
    web_info = website_data.get("web", {})

    if not web_info.get("https_enabled", False):
        score += 25
        findings.append("HTTPS is not enforced or unreachable on standard ports")
        recommendations.append("Enable and enforce HTTPS with HSTS redirection across all subdomains")
    
    if ssl_info.get("ssl_status") != "Valid":
        score += 30
        findings.append(f"SSL certificate issue: {ssl_info.get('ssl_status', 'Invalid')}")
        recommendations.append("Install a valid, trusted SSL/TLS certificate (e.g. Let's Encrypt)")
    elif ssl_info.get("days_remaining", 999) < 15:
        score += 15
        findings.append(f"SSL certificate expiring soon ({ssl_info.get('days_remaining')} days remaining)")
        recommendations.append("Renew the SSL certificate to prevent browser warning disruptions")

    # 2. Security Headers
    missing_headers = web_info.get("missing_headers", [])
    if missing_headers:
        # e.g. 5 points for missing HSTS, CSP, or X-Frame-Options
        penalty = min(25, len(missing_headers) * 4)
        score += penalty
        missing_names = [h[0] for h in missing_headers[:3]]
        findings.append(f"Missing {len(missing_headers)} critical security headers ({', '.join(missing_names)})")
        recommendations.append("Configure missing HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)")

    # 3. Server Banner Disclosure
    server_banner = web_info.get("server_banner", "")
    if server_banner and server_banner not in ("Not Disclosed", "Unknown"):
        score += 10
        findings.append(f"Web server version disclosed in HTTP headers: {server_banner}")
        recommendations.append("Mask or suppress the 'Server' and 'X-Powered-By' response headers in web server config")

    # 4. DNS Security (SPF & DMARC)
    dns_info = domain_data.get("dns", {})
    if not dns_info.get("has_spf", False):
        score += 10
        findings.append("Missing SPF (Sender Policy Framework) TXT record")
        recommendations.append("Publish an SPF record to protect against email spoofing and phishing")
    
    if not dns_info.get("has_dmarc", False):
        score += 10
        findings.append("Missing DMARC authentication policy record")
        recommendations.append("Implement a DMARC policy (_dmarc.yourdomain.com) to monitor email integrity")

    # 5. Exposed Subdomains
    if len(subdomain_data) >= 5:
        score += 10
        findings.append(f"High public attack surface ({len(subdomain_data)} publicly discoverable subdomains)")
        recommendations.append("Audit all public subdomains to decommission unused or dangling DNS records")

    # 6. Email Compromise / Exposure
    if email_data.get("breach_found", False):
        score += 25
        findings.append("Target email appears in known public breach or credential leak datasets")
        recommendations.append("Immediately rotate email passwords and enforce Multi-Factor Authentication (MFA)")

    # Cap exposure score
    exposure_score = min(100, max(0, score))

    if exposure_score <= 30:
        level = "LOW"
    elif exposure_score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    if not findings:
        findings.append("Good baseline security posture. No high-risk exposures detected.")

    return {
        "score": exposure_score,
        "level": level,
        "findings": findings,
        "recommendations": recommendations,
    }
