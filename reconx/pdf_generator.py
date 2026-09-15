"""
PDF Report Generator for ReconX.
Generates an executive cybersecurity audit report with custom company branding,
GeoIP, WHOIS, Port scanning, SSL CT history, and OWASP audit tables.
"""

import os
from datetime import datetime
from typing import Dict, Any
from fpdf import FPDF
from fpdf.enums import XPos, YPos


class ReconXPDF(FPDF):
    def __init__(self, company_name: str = "CYBER DEFENSE INTELLIGENCE LABS"):
        super().__init__()
        self.company_name = company_name
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        # Top Company Banner
        self.set_fill_color(20, 32, 54)  # Deep Navy #142036
        self.rect(0, 0, 210, 22, "F")

        # Company Title
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(255, 255, 255)
        self.set_xy(12, 6)
        self.cell(100, 6, self.company_name, border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")

        # Confidentiality Tag
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(220, 53, 69)  # Red accent
        self.set_xy(120, 6)
        self.cell(78, 6, "CONFIDENTIAL // SECURITY AUDIT", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="R")

        # Sub-header bar
        self.set_font("Helvetica", "", 7)
        self.set_text_color(180, 195, 215)
        self.set_xy(12, 13)
        self.cell(100, 5, "ReconX Surface Exposure & Public OSINT Intelligence Report", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")

        self.set_xy(120, 13)
        self.cell(78, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="R")

        self.ln(15)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 130, 145)
        self.set_draw_color(220, 225, 230)
        self.line(10, self.get_y() - 2, 200, self.get_y() - 2)
        self.cell(95, 8, f"{self.company_name} - For Authorized Use Only", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")
        self.cell(95, 8, f"Page {self.page_no()}/{{nb}}", border=0, new_x=XPos.RIGHT, new_y=YPos.TOP, align="R")

    def section_header(self, title: str):
        """Draws a themed section title bar."""
        self.ln(3)
        self.set_fill_color(240, 244, 250)
        self.set_draw_color(13, 110, 253)  # Blue border
        self.set_text_color(20, 32, 54)
        self.set_font("Helvetica", "B", 10)
        self.cell(190, 7, f"  {title.upper()}", border="L", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)


def generate_pdf_report(
    report_data: Dict[str, Any],
    output_path: str,
    company_name: str = "CYBER DEFENSE INTELLIGENCE LABS"
) -> str:
    """
    Builds and saves an executive security PDF report from ReconX data.
    """
    pdf = ReconXPDF(company_name=company_name)
    pdf.alias_nb_pages()
    pdf.add_page()

    target = report_data.get("target", "Unknown")
    root_domain = report_data.get("root_domain", "")
    domain_data = report_data.get("domain", {})
    port_data = report_data.get("ports", {})
    website_data = report_data.get("website", {})
    subdomains = report_data.get("subdomains", [])
    email_data = report_data.get("email")
    exposure = report_data.get("exposure", {})

    score = exposure.get("score", 0)
    level = exposure.get("level", "LOW")

    # 1. Executive Summary & Exposure Score Card
    pdf.set_fill_color(248, 249, 252)
    pdf.set_draw_color(220, 226, 235)
    pdf.rect(10, 28, 190, 32, "FD")

    # Target info left side
    target_display = f"{target}"
    if root_domain and root_domain != target:
        target_display += f" (Apex: {root_domain})"

    pdf.set_xy(14, 31)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(20, 32, 54)
    pdf.cell(110, 6, f"Target: {target_display}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(14)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 110, 125)
    primary_ip = domain_data.get("ip_info", {}).get("primary_ip", "Unknown")
    geoip = domain_data.get("geoip", {})
    pdf.cell(110, 5, f"IP Address: {primary_ip} | Location: {geoip.get('city', '')}, {geoip.get('country', '')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_x(14)
    pdf.cell(110, 5, f"ISP / Org  : {geoip.get('isp', 'Unknown')} ({geoip.get('asn', '')})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Risk Badge right side
    if level == "HIGH":
        badge_bg = (220, 53, 69)
    elif level == "MEDIUM":
        badge_bg = (253, 126, 20)
    else:
        badge_bg = (40, 167, 69)

    pdf.set_fill_color(*badge_bg)
    pdf.rect(138, 31, 58, 26, "F")

    pdf.set_xy(138, 33)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(58, 7, f"{score} / 100", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(138, 41)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(58, 5, f"EXPOSURE: {level}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_xy(138, 47)
    pdf.set_font("Helvetica", "", 7)
    pdf.cell(58, 5, "Overall Risk Posture", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(63)

    # Helper table row printer
    def table_row(col1: str, col2: str, is_alt: bool = False, col2_color=None):
        if is_alt:
            pdf.set_fill_color(248, 250, 253)
        else:
            pdf.set_fill_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(60, 70, 85)
        pdf.cell(55, 6, f"  {col1}", border="B", fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 8)
        if col2_color:
            pdf.set_text_color(*col2_color)
        else:
            pdf.set_text_color(20, 25, 35)
        pdf.cell(135, 6, f"{col2}", border="B", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # 1. Infrastructure & Geolocation
    pdf.section_header("1. Infrastructure, Geolocation & Open Ports")
    table_row("Primary IPv4", primary_ip, False)
    table_row("Location", f"{geoip.get('city', '')}, {geoip.get('country', '')}", True)
    table_row("ISP / Host", geoip.get("isp", "Unknown"), False)
    table_row("ASN Network", geoip.get("asn", "Unknown"), True)
    table_row("Open Ports", port_data.get("summary", "None (Filtered)"), False)

    web_info = website_data.get("web", {})
    waf_str = web_info.get("waf_detected")
    if waf_str and waf_str != "None Detected (Direct Origin / Generic)":
        table_row("WAF / CDN", waf_str, True, (13, 110, 253))

    # 2. Registrar & WHOIS
    pdf.section_header("2. Registrar & WHOIS Intelligence")
    whois_info = domain_data.get("whois", {})
    table_row("Registrar", whois_info.get("registrar", "Not Disclosed"), False)
    table_row("Registration Date", whois_info.get("created_date", "Unknown"), True)
    table_row("Expiration Date", whois_info.get("expires_date", "Unknown"), False)
    domain_status = "Parked Nameservers Detected" if domain_data.get("is_parked") else "Active"
    table_row("Domain Status", domain_status, True, (253, 126, 20) if domain_data.get("is_parked") else None)

    # 3. DNS & Email Authentication
    pdf.section_header("3. DNS Records & Anti-Spoofing Posture")
    dns_info = domain_data.get("dns", {})
    table_row("A Records", ", ".join(dns_info.get("a", [])) or "None", False)
    table_row("MX Records", ", ".join(dns_info.get("mx", [])) or "None", True)
    table_row("NS Records", ", ".join(dns_info.get("ns", [])) or "None", False)
    
    spf_status = "Configured (PASS)" if dns_info.get("has_spf") else "Missing (FAIL - Vulnerable to Spoofing)"
    spf_color = (40, 167, 69) if dns_info.get("has_spf") else (220, 53, 69)
    table_row("SPF Record", spf_status, True, spf_color)
    
    dmarc_status = "Configured (PASS)" if dns_info.get("has_dmarc") else "Missing (FAIL - No DMARC Enforcement)"
    dmarc_color = (40, 167, 69) if dns_info.get("has_dmarc") else (220, 53, 69)
    table_row("DMARC Record", dmarc_status, False, dmarc_color)

    if dns_info.get("has_dnssec"):
        table_row("DNSSEC", "Active (Cryptographic Validation Enabled)", True, (40, 167, 69))
    if dns_info.get("has_caa"):
        table_row("CAA Policy", "Configured (Restricts CA issuance)", False, (40, 167, 69))

    # 4. SSL / Certificate Intelligence
    pdf.section_header("4. SSL / TLS Certificate Intelligence")
    ssl_info = website_data.get("ssl", {})
    ssl_color = (40, 167, 69) if "Valid" in ssl_info.get("ssl_status", "") else (220, 53, 69)
    table_row("Certificate Status", ssl_info.get("ssl_status", "Not Available"), False, ssl_color)
    table_row("Issuer CA", ssl_info.get("issuer", "Unknown"), True)
    table_row("Expires On", ssl_info.get("expires_on", "Unknown"), False)
    if ssl_info.get("note"):
        table_row("Audit Note", ssl_info.get("note"), True, (100, 110, 125))

    # 5. Website Security & Headers
    pdf.section_header("5. Website Security & OWASP Headers")
    table_row("HTTPS Status", "Enabled" if web_info.get("https_enabled") else "Disabled / Offline", False)
    table_row("Server Header", web_info.get("server_banner", "Not Disclosed"), True)
    table_row("robots.txt / sitemap", f"robots: {'Found' if web_info.get('robots_found') else 'Not Found'} | sitemap: {'Found' if web_info.get('sitemap_found') else 'Not Found'}", False)
    if web_info.get("security_txt_found"):
        table_row("security.txt", "Configured (RFC 9116 Disclosure Policy)", True, (40, 167, 69))
    table_row("Security Headers", f"{web_info.get('headers_score_str', '0/7')} Headers Present", False)

    # 6. Subdomains
    pdf.section_header("6. Discovered Public Subdomains")
    if subdomains:
        sub_str = ", ".join(subdomains[:12])
        if len(subdomains) > 12:
            sub_str += f" ... (+{len(subdomains)-12} more)"
        table_row(f"Subdomains ({len(subdomains)})", sub_str, False)
    else:
        table_row("Subdomains", "No public subdomains discovered via CT logs or DNS", False)

    # 7. Harvested OSINT Intelligence (theHarvester Engine)
    harvester_data = report_data.get("harvester", {})
    emails_harvested = harvester_data.get("emails", [])
    if emails_harvested or harvester_data.get("users"):
        pdf.section_header("7. theHarvester OSINT Intelligence")
        if emails_harvested:
            email_summary = ", ".join(e["email"] for e in emails_harvested[:8])
            if len(emails_harvested) > 8:
                email_summary += f" ... (+{len(emails_harvested)-8} more)"
            table_row(f"Harvested Emails ({len(emails_harvested)})", email_summary, False)
        if harvester_data.get("users"):
            table_row("Identified Contacts", ", ".join(harvester_data.get("users", [])[:4]), True)

    # 8. Optional Specific Target Email Section
    if email_data:
        pdf.section_header("8. Email Breach & Compromise Analysis")
        table_row("Target Email", email_data.get("email", "N/A"), False)
        table_row("Breach Check", email_data.get("breach_status", "N/A"), True)

    # 9. Hardening Recommendations
    pdf.section_header("Hardening & Security Recommendations")
    recs = exposure.get("recommendations", [])
    if recs:
        for r in recs:
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(40, 45, 55)
            pdf.cell(5, 5, "-", new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.multi_cell(185, 5, r)
    else:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(40, 167, 69)
        pdf.cell(190, 5, "No critical remediation actions needed. Baseline security looks good!", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    abs_output = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_output), exist_ok=True)
    pdf.output(abs_output)
    return abs_output
