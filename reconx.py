#!/usr/bin/env python3
"""
ReconX - Main CLI & Interactive Entry Point
Advanced Passive Domain, GeoIP, WHOIS, Port Scan, SSL, and Subdomain OSINT Scanner.
"""

import sys
import os
import argparse

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reconx.core import scan_target
from reconx.reporter import render_report, render_json
from reconx.pdf_generator import generate_pdf_report
from reconx.html_generator import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="ReconX - Advanced Public OSINT & Exposure Assessment Scanner"
    )
    parser.add_argument(
        "-t", "--target",
        help="Target URL or domain (e.g. https://example.com or example.com)"
    )
    parser.add_argument(
        "-e", "--email",
        default=None,
        help="Optional target email to audit (e.g. admin@example.com)"
    )
    parser.add_argument(
        "--pdf",
        nargs="?",
        const="auto",
        default=None,
        help="Download/export findings as professional PDF report (optional output path)"
    )
    parser.add_argument(
        "--html",
        nargs="?",
        const="auto",
        default=None,
        help="Export findings as interactive HTML report (optional output path)"
    )
    parser.add_argument(
        "--harvest", "--harvester",
        action="store_true",
        help="Enable aggressive theHarvester-style OSINT email & host discovery"
    )
    parser.add_argument(
        "--company",
        default="CYBER DEFENSE INTELLIGENCE LABS",
        help="Custom Company/Organization name for top header banner in PDF/HTML"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    is_interactive = False
    target = args.target
    email = args.email

    # If target not passed as command-line flag, prompt interactively
    if not target:
        is_interactive = True
        try:
            print("\nEnter Target:")
            target = input().strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not target:
        print("Error: Target cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if is_interactive and not args.json:
        print(f"\n[*] Initiating ReconX Advanced Scan on: {target}")
        print("    -> Resolving IP Geolocation, ASN & ISP...")
        print("    -> Auditing DNS, SPF, DMARC, DNSSEC & CAA records...")
        print("    -> Querying RDAP Registrar & WHOIS data...")
        print("    -> Scanning common service ports...")
        print("    -> Probing Website, WAF, SSL & CT logs...")
        print("    -> Discovering public subdomains...")
        print("    -> Harvesting public emails & contacts (theHarvester OSINT engine)...")

    try:
        report = scan_target(target, email)
    except Exception as e:
        print(f"\nScanning failed: {e}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(render_json(report))
    else:
        print("")
        print(render_report(report, use_color=not args.no_color))

    # PDF & HTML Export Handling
    pdf_dest = args.pdf
    html_dest = args.html
    company = args.company

    if is_interactive and not args.json and not args.pdf and not args.html:
        try:
            print("\n" + "=" * 45)
            ans = input("Download full report as PDF/HTML? (Y/n) [Y]: ").strip().lower()
            if ans in ("", "y", "yes"):
                comp_input = input(f"Enter Company Name [{company}]: ").strip()
                if comp_input:
                    company = comp_input
                pdf_dest = "auto"
                html_dest = "auto"
        except (KeyboardInterrupt, EOFError):
            pass

    clean_name = report.get("root_domain", report.get("target", "scan")).replace(".", "_")

    if pdf_dest:
        if pdf_dest == "auto":
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_dest = f"reports/reconx_{clean_name}_{timestamp}.pdf"

        try:
            saved_path = generate_pdf_report(report, pdf_dest, company_name=company)
            print(f"\n[+] PDF Report downloaded successfully:")
            print(f"    -> {saved_path}")
        except Exception as e:
            print(f"\n[-] Failed to generate PDF: {e}", file=sys.stderr)

    if html_dest:
        if html_dest == "auto":
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_dest = f"reports/reconx_{clean_name}_{timestamp}.html"

        try:
            saved_html = generate_html_report(report, html_dest, company_name=company)
            print(f"\n[+] Interactive HTML Report generated successfully:")
            print(f"    -> {saved_html}")
        except Exception as e:
            print(f"\n[-] Failed to generate HTML: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
