"""
Console CLI and JSON reporter for ReconX.
Renders advanced intelligence cards including GeoIP, WHOIS, DNS, ports, and SSL.
"""

import sys
import json
from typing import Dict, Any


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
GRAY = "\033[90m"


def _supports_color() -> bool:
    """Check if the current terminal supports color output."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def render_report(report: Dict[str, Any], use_color: bool = True) -> str:
    """
    Renders an advanced, comprehensive terminal security intelligence card.
    """
    color = use_color and _supports_color()

    target = report.get("target", "Unknown")
    root_domain = report.get("root_domain", "")
    domain_data = report.get("domain", {})
    port_data = report.get("ports", {})
    website_data = report.get("website", {})
    subdomains = report.get("subdomains", [])
    email_data = report.get("email")
    exposure = report.get("exposure", {})

    ssl_info = website_data.get("ssl", {})
    web_info = website_data.get("web", {})
    dns_info = domain_data.get("dns", {})
    whois_info = domain_data.get("whois", {})
    geoip = domain_data.get("geoip", {})

    ip_address = domain_data.get("ip_info", {}).get("primary_ip", "Unknown")
    https_status = "Enabled" if web_info.get("https_enabled", False) else "Disabled"
    ssl_status = ssl_info.get("ssl_status", "Not Available")
    server_str = web_info.get("server_banner", "Not Disclosed")

    a_status = "Found" if dns_info.get("has_a", False) else "Not Found"
    mx_status = "Found" if dns_info.get("has_mx", False) else "Not Found"
    ns_status = "Found" if dns_info.get("has_ns", False) else "Not Found"
    spf_status = "Configured (PASS)" if dns_info.get("has_spf", False) else "Missing (FAIL)"
    dmarc_status = "Configured (PASS)" if dns_info.get("has_dmarc", False) else "Missing (FAIL)"

    robots_status = "Found" if web_info.get("robots_found", False) else "Not Found"
    sitemap_status = "Found" if web_info.get("sitemap_found", False) else "Not Found"
    headers_score = web_info.get("headers_score_str", "0/7")

    score = exposure.get("score", 0)
    level = exposure.get("level", "LOW")

    # Colorize Level & Score
    if color:
        if level == "HIGH":
            level_str = f"{BOLD}{RED}{level}{RESET}"
            score_str = f"{BOLD}{RED}{score}/100{RESET}"
        elif level == "MEDIUM":
            level_str = f"{BOLD}{YELLOW}{level}{RESET}"
            score_str = f"{BOLD}{YELLOW}{score}/100{RESET}"
        else:
            level_str = f"{BOLD}{GREEN}{level}{RESET}"
            score_str = f"{BOLD}{GREEN}{score}/100{RESET}"
    else:
        level_str = level
        score_str = f"{score}/100"

    header_bar = "=" * 32
    sub_bar = "-" * 32

    lines = []
    lines.append(f"{CYAN if color else ''}{header_bar}")
    lines.append("          RECONX ADVANCED")
    lines.append(f"{header_bar}{RESET if color else ''}")
    lines.append("")

    target_display = f"{target}"
    if root_domain and root_domain != target:
        target_display += f" (Apex: {root_domain})"
    lines.append(f"TARGET: {target_display}")
    lines.append("")

    # [INFRASTRUCTURE & GEOLOCATION]
    lines.append(f"{BOLD if color else ''}[INFRASTRUCTURE & GEOLOCATION]{RESET if color else ''}")
    lines.append(f"IP Address       : {ip_address}")
    if geoip.get("country") != "Unknown":
        lines.append(f"Location         : {geoip.get('city', '')}, {geoip.get('country', '')}")
        lines.append(f"ISP / Provider   : {geoip.get('isp', '')}")
        lines.append(f"ASN              : {geoip.get('asn', '')}")
    waf_str = web_info.get("waf_detected")
    if waf_str and waf_str != "None Detected (Direct Origin / Generic)":
        lines.append(f"WAF / CDN        : {waf_str}")

    open_ports_summary = port_data.get("summary", "None")
    lines.append(f"Open Ports       : {open_ports_summary}")
    lines.append("")

    # [REGISTRAR & WHOIS]
    lines.append(f"{BOLD if color else ''}[REGISTRAR & WHOIS]{RESET if color else ''}")
    lines.append(f"Registrar        : {whois_info.get('registrar', 'Not Disclosed')}")
    lines.append(f"Created Date     : {whois_info.get('created_date', 'Unknown')}")
    lines.append(f"Expires Date     : {whois_info.get('expires_date', 'Unknown')}")
    if domain_data.get("is_parked"):
        lines.append(f"Domain Status    : Parked / Parking Nameservers Detected")
    lines.append("")

    # [DNS & EMAIL POSTURE]
    lines.append(f"{BOLD if color else ''}[DNS & EMAIL SECURITY]{RESET if color else ''}")
    lines.append(f"A Record         : {a_status}")
    lines.append(f"MX Record        : {mx_status}")
    lines.append(f"NS Record        : {ns_status}")
    lines.append(f"SPF Record       : {spf_status}")
    lines.append(f"DMARC Record     : {dmarc_status}")
    if dns_info.get("has_dnssec"):
        lines.append(f"DNSSEC           : Active (DS Record Found)")
    if dns_info.get("has_caa"):
        lines.append(f"CAA Record       : Configured")
    lines.append("")

    # [SSL / CERTIFICATE]
    lines.append(f"{BOLD if color else ''}[SSL / CERTIFICATE INTELLIGENCE]{RESET if color else ''}")
    lines.append(f"SSL Status       : {ssl_status}")
    if ssl_info.get("issuer") not in ("Unknown", "N/A"):
        lines.append(f"Issuer           : {ssl_info.get('issuer')}")
    if ssl_info.get("expires_on") not in ("Unknown", "N/A"):
        lines.append(f"Expires On       : {ssl_info.get('expires_on')}")
    if ssl_info.get("note"):
        lines.append(f"Note             : {ssl_info.get('note')}")
    lines.append("")

    # [SUBDOMAINS]
    lines.append(f"{BOLD if color else ''}[SUBDOMAINS]{RESET if color else ''}")
    if subdomains:
        for sub in subdomains[:8]:
            lines.append(f"{sub}")
        if len(subdomains) > 8:
            lines.append(f"... (+{len(subdomains)-8} more discovered)")
    else:
        lines.append("None Discovered")
    lines.append("")

    # [WEBSITE]
    lines.append(f"{BOLD if color else ''}[WEBSITE]{RESET if color else ''}")
    lines.append(f"HTTPS            : {https_status}")
    lines.append(f"Server           : {server_str}")
    lines.append(f"robots.txt       : {robots_status}")
    lines.append(f"sitemap.xml      : {sitemap_status}")
    if web_info.get("security_txt_found"):
        lines.append(f"security.txt     : Found (RFC 9116)")
    lines.append(f"Security Headers : {headers_score}")
    lines.append("")

    # [EMAIL] (Only if email passed)
    if email_data:
        lines.append(f"{BOLD if color else ''}[EMAIL OSINT]{RESET if color else ''}")
        lines.append(f"Target Email     : {email_data.get('email', 'N/A')}")
        lines.append(f"Format           : {email_data.get('format_status', 'N/A')}")
        lines.append(f"Public Exposure  : {email_data.get('public_exposure', 'N/A')}")
    # [PASSIVE OSINT HARVESTER (theHarvester Engine)]
    harvester_data = report.get("harvester", {})
    emails_harvested = harvester_data.get("emails", [])
    users_harvested = harvester_data.get("users", [])
    if emails_harvested or users_harvested:
        lines.append(f"{BOLD if color else ''}[PASSIVE OSINT HARVESTER (theHarvester Engine)]{RESET if color else ''}")
        if emails_harvested:
            lines.append(f"Discovered Emails ({len(emails_harvested)}):")
            for item in emails_harvested[:6]:
                lines.append(f"  * {item['email']} [{item.get('source', 'OSINT')}]")
            if len(emails_harvested) > 6:
                lines.append(f"  * ... (+{len(emails_harvested)-6} more)")
        if users_harvested:
            lines.append(f"Discovered Contacts: {', '.join(users_harvested[:4])}")
        lines.append("")

    # EXPOSURE SCORE
    lines.append(f"{sub_bar}")
    lines.append(f"EXPOSURE SCORE: {score_str}")
    lines.append(f"LEVEL: {level_str}")
    lines.append(f"{sub_bar}")

    # Key Findings
    findings = exposure.get("findings", [])
    if findings:
        lines.append("")
        lines.append(f"{BOLD if color else ''}Key Findings:{RESET if color else ''}")
        for f in findings[:4]:
            lines.append(f"- {f}")

    return "\n".join(lines)


def render_json(report: Dict[str, Any]) -> str:
    """Render full recon report as JSON."""
    return json.dumps(report, indent=2)
