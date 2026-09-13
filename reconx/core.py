"""
ReconX core engine.
Coordinates domain intelligence, GeoIP, WHOIS, port scanning,
SSL & web security headers, subdomain discovery, and exposure assessment.
"""

from typing import Dict, Any, Optional

from reconx.domain_recon import normalize_domains, analyze_domain
from reconx.port_scanner import scan_ports
from reconx.website_recon import analyze_website
from reconx.subdomain_recon import discover_subdomains
from reconx.email_recon import analyze_email
from reconx.scoring import calculate_exposure_score


def scan_target(target: str, email: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform deep, multi-stage OSINT and exposure assessment on target.
    """
    host, root_domain = normalize_domains(target)
    if not root_domain and not host:
        raise ValueError("Invalid target domain or URL provided.")

    # 1. Domain, DNS, GeoIP & WHOIS
    domain_data = analyze_domain(target)
    primary_ip = domain_data.get("ip_info", {}).get("primary_ip", "Unknown")

    # 2. Fast Multi-Threaded Port Scanner
    port_data = scan_ports(primary_ip)

    # 3. Website & SSL Recon (with CT Fallback)
    website_data = analyze_website(host, root_domain)

    # 4. Subdomain Recon
    subdomain_data = discover_subdomains(root_domain)

    # 5. Email OSINT (Only if user provided an email or explicit flag)
    email_data = None
    if email and email.strip():
        email_data = analyze_email(email.strip())

    # 6. Exposure Scoring
    exposure_data = calculate_exposure_score(domain_data, website_data, subdomain_data, email_data or {})

    return {
        "target": host,
        "root_domain": root_domain,
        "domain": domain_data,
        "ports": port_data,
        "website": website_data,
        "subdomains": subdomain_data,
        "email": email_data,
        "exposure": exposure_data,
    }
