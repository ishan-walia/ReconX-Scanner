"""
Unit tests for ReconX OSINT & Exposure Scanner.
"""

import unittest
import json
from reconx.domain_recon import extract_domain
from reconx.email_recon import validate_email_format
from reconx.scoring import calculate_exposure_score
from reconx.reporter import render_report, render_json


class TestReconX(unittest.TestCase):
    def test_extract_domain(self):
        self.assertEqual(extract_domain("https://example.com"), "example.com")
        self.assertEqual(extract_domain("http://example.com/test?param=1"), "example.com")
        self.assertEqual(extract_domain("https://sub.domain.co.uk:8443/"), "sub.domain.co.uk")
        self.assertEqual(extract_domain("EXAMPLE.COM/"), "example.com")

    def test_email_validation(self):
        self.assertTrue(validate_email_format("admin@example.com"))
        self.assertTrue(validate_email_format("security.team+alerts@company.org"))
        self.assertFalse(validate_email_format("invalid-email"))
        self.assertFalse(validate_email_format("@missing-user.com"))
        self.assertFalse(validate_email_format("user@"))

    def test_scoring_engine_low_risk(self):
        domain_data = {"dns": {"has_spf": True, "has_dmarc": True}}
        website_data = {
            "ssl": {"ssl_status": "Valid", "days_remaining": 120},
            "web": {
                "https_enabled": True,
                "server_banner": "Not Disclosed",
                "missing_headers": []
            }
        }
        subdomain_data = ["www.example.com"]
        email_data = {"breach_found": False}

        result = calculate_exposure_score(domain_data, website_data, subdomain_data, email_data)
        self.assertEqual(result["level"], "LOW")
        self.assertLessEqual(result["score"], 30)

    def test_scoring_engine_high_risk(self):
        domain_data = {"dns": {"has_spf": False, "has_dmarc": False}}
        website_data = {
            "ssl": {"ssl_status": "Expired", "days_remaining": -5},
            "web": {
                "https_enabled": False,
                "server_banner": "Apache/2.4.41 (Ubuntu)",
                "missing_headers": [("HSTS", ""), ("CSP", ""), ("X-Frame-Options", "")]
            }
        }
        subdomain_data = ["sub1", "sub2", "sub3", "sub4", "sub5", "sub6"]
        email_data = {"breach_found": True}

        result = calculate_exposure_score(domain_data, website_data, subdomain_data, email_data)
        self.assertEqual(result["level"], "HIGH")
        self.assertGreaterEqual(result["score"], 61)

    def test_reporter_layout(self):
        mock_report = {
            "target": "example.com",
            "root_domain": "example.com",
            "domain": {
                "ip_info": {"primary_ip": "93.184.216.34"},
                "geoip": {"country": "United States (US)", "city": "Los Angeles", "isp": "EDGECAST", "asn": "AS15133"},
                "whois": {"registrar": "Example Registrar", "created_date": "1995-01-01", "expires_date": "2027-01-01"},
                "dns": {"has_a": True, "has_mx": True, "has_ns": True, "has_spf": True, "has_dmarc": True}
            },
            "ports": {"summary": "80 (HTTP), 443 (HTTPS)"},
            "website": {
                "ssl": {"ssl_status": "Valid", "issuer": "DigiCert", "expires_on": "2027-01-01"},
                "web": {
                    "https_enabled": True,
                    "server_banner": "nginx",
                    "robots_found": True,
                    "sitemap_found": True,
                    "headers_score_str": "5/7"
                }
            },
            "subdomains": ["www.example.com", "mail.example.com", "blog.example.com"],
            "email": {
                "email": "admin@example.com",
                "format_status": "Valid",
                "public_exposure": "Found",
                "breach_status": "No Match"
            },
            "exposure": {
                "score": 24,
                "level": "LOW",
                "findings": []
            }
        }

        output = render_report(mock_report, use_color=False)
        self.assertIn("RECONX", output)
        self.assertIn("TARGET: example.com", output)
        self.assertIn("[INFRASTRUCTURE & GEOLOCATION]", output)
        self.assertIn("IP Address       : 93.184.216.34", output)
        self.assertIn("[REGISTRAR & WHOIS]", output)
        self.assertIn("Registrar        : Example Registrar", output)
        self.assertIn("[DNS & EMAIL SECURITY]", output)
        self.assertIn("A Record         : Found", output)
        self.assertIn("MX Record        : Found", output)
        self.assertIn("[SSL / CERTIFICATE INTELLIGENCE]", output)
        self.assertIn("SSL Status       : Valid", output)
        self.assertIn("[SUBDOMAINS]", output)
        self.assertIn("www.example.com", output)
        self.assertIn("[WEBSITE]", output)
        self.assertIn("Security Headers : 5/7", output)
        self.assertIn("EXPOSURE SCORE: 24/100", output)
        self.assertIn("LEVEL: LOW", output)

    def test_json_rendering(self):
        mock_report = {"target": "example.com", "exposure": {"score": 24}}
        json_out = render_json(mock_report)
        parsed = json.loads(json_out)
        self.assertEqual(parsed["target"], "example.com")

    def test_pdf_report_generation(self):
        import tempfile
        import os
        from reconx.pdf_generator import generate_pdf_report

        mock_report = {
            "target": "example.com",
            "domain": {
                "ip_info": {"primary_ip": "93.184.216.34"},
                "dns": {"has_a": True, "has_mx": True, "has_ns": True, "has_spf": True, "has_dmarc": True},
                "whois": {"registrar": "Example Registrar", "created_date": "1995-01-01"}
            },
            "website": {
                "ssl": {"ssl_status": "Valid", "issuer": "DigiCert", "expires_on": "2027-01-01"},
                "web": {
                    "https_enabled": True,
                    "server_banner": "nginx",
                    "robots_found": True,
                    "sitemap_found": True,
                    "headers_score_str": "5/7",
                    "missing_headers": [("Strict-Transport-Security", "")]
                }
            },
            "subdomains": ["www.example.com", "mail.example.com"],
            "email": {
                "email": "admin@example.com",
                "format_status": "Valid",
                "public_exposure": "Found",
                "breach_status": "No Match",
                "breach_found": False
            },
            "exposure": {
                "score": 15,
                "level": "LOW",
                "findings": ["Sample finding"],
                "recommendations": ["Sample recommendation"]
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_pdf = os.path.join(tmpdir, "audit_report.pdf")
            saved = generate_pdf_report(mock_report, out_pdf, company_name="ACME SECURITY LABS")
            self.assertTrue(os.path.exists(saved))
            self.assertGreater(os.path.getsize(saved), 1000)

    def test_waf_detection(self):
        from reconx.website_recon import detect_waf_and_cdn
        # Test Cloudflare detection
        cf_headers = {"cf-ray": "82348abc", "server": "cloudflare"}
        self.assertIn("Cloudflare", detect_waf_and_cdn(cf_headers, "cloudflare"))

        # Test CloudFront detection
        aws_headers = {"via": "1.1 cloudfront.net", "x-amz-cf-id": "xyz"}
        self.assertIn("CloudFront", detect_waf_and_cdn(aws_headers, "AmazonS3"))

        # Test None detected
        generic_headers = {"content-type": "text/html"}
        self.assertIn("None Detected", detect_waf_and_cdn(generic_headers, "Apache/2.4"))

    def test_html_report_generation(self):
        import tempfile
        import os
        from reconx.html_generator import generate_html_report

        mock_report = {
            "target": "example.com",
            "root_domain": "example.com",
            "domain": {
                "ip_info": {"primary_ip": "93.184.216.34"},
                "dns": {"has_a": True, "has_mx": True, "has_ns": True, "has_spf": True, "has_dmarc": True, "has_dnssec": True},
                "whois": {"registrar": "Example Registrar", "created_date": "1995-01-01"}
            },
            "website": {
                "ssl": {"ssl_status": "Valid", "issuer": "DigiCert", "expires_on": "2027-01-01"},
                "web": {
                    "https_enabled": True,
                    "server_banner": "nginx",
                    "waf_detected": "Cloudflare (WAF/CDN)",
                    "robots_found": True,
                    "sitemap_found": True,
                    "security_txt_found": True,
                    "headers_score_str": "6/7",
                    "present_headers": [("Strict-Transport-Security", "max-age=31536000")],
                    "missing_headers": [("Content-Security-Policy", "Missing")]
                }
            },
            "subdomains": ["www.example.com", "api.example.com"],
            "ports": {"summary": "80 (HTTP), 443 (HTTPS)"},
            "exposure": {
                "score": 15,
                "level": "LOW",
                "findings": ["Subdomains discovered"],
                "recommendations": ["Audit subdomains"]
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_html = os.path.join(tmpdir, "report.html")
            saved = generate_html_report(mock_report, out_html, company_name="ACME SECURITY LABS")
            self.assertTrue(os.path.exists(saved))
            with open(saved, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("ACME SECURITY LABS", content)
            self.assertIn("example.com", content)
            self.assertIn("Cloudflare", content)

    def test_harvester_engine(self):
        from reconx.harvester import run_harvester
        # Run harvester on mock domain
        result = run_harvester("example.com", "example.com", has_mx=True, subdomain_list=["www.example.com"])
        self.assertEqual(result["engine"], "ReconX Passive theHarvester OSINT Engine")
        self.assertEqual(result["target"], "example.com")
        self.assertIsInstance(result["emails"], list)
        self.assertIsInstance(result["hosts"], list)
        self.assertGreaterEqual(result["total_hosts"], 1)


if __name__ == "__main__":
    unittest.main()
