# ReconX 🔍

**ReconX** is a passive OSINT (Open Source Intelligence) and security surface exposure assessment tool built in Python. It aggregates publicly available domain, DNS, SSL, web security headers, subdomain, and email intelligence without invasive probing or exploitation, and computes an **Exposure Score (0–100)**.

---

## 🚀 Features

1. **Domain & DNS Reconnaissance**:
   - Primary IPv4 & IPv6 resolution.
   - DNS record verification: **A**, **MX**, **NS**, **TXT**.
   - Email authentication auditing: **SPF** (`v=spf1`) and **DMARC** (`_dmarc.domain`).
   - Public RDAP / WHOIS registrar and creation date lookup.
2. **Website & SSL Security Audit**:
   - HTTP to HTTPS redirection status.
   - Live SSL/TLS certificate validation (issuer, expiration date, days remaining, protocol version).
   - Server & technology disclosure detection (`Server`, `X-Powered-By`).
   - **OWASP Security Headers Audit**: Evaluates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy (`x/7` score).
   - Probes public exposure files: `robots.txt` and `sitemap.xml`.
3. **Subdomain Discovery**:
   - Passively queries Certificate Transparency logs (**crt.sh**) to uncover historical subdomains without sending direct traffic.
   - Rapid concurrent DNS resolution to identify active subdomains (`www`, `mail`, `blog`, `api`, etc.).
4. **Email OSINT & Exposure Check**:
   - RFC email syntax validation.
   - Mail routing verification.
   - Privacy-preserving public breach check via k-anonymity hash-range inspection.
5. **Exposure & Risk Scoring Engine**:
   - `0  – 30` : **LOW** 🟢
   - `31 – 60` : **MEDIUM** 🟡
   - `61 – 100`: **HIGH** 🔴
   - Generates specific findings and actionable hardening recommendations.

---

## 📁 Directory Structure

```
reconx/
├── reconx/
│   ├── __init__.py
│   ├── core.py              # Central orchestrator
│   ├── domain_recon.py      # IP, DNS (A, MX, NS, TXT), RDAP
│   ├── website_recon.py     # SSL cert, HTTPS, security headers, robots, sitemap
│   ├── subdomain_recon.py   # Certificate Transparency & DNS subdomains
│   ├── email_recon.py       # Email format, mail routing, breach check
│   ├── scoring.py           # Exposure score (0-100) & recommendation engine
│   └── reporter.py          # Terminal banner & JSON formatter
├── tests/
│   └── test_reconx.py       # Unit test suite
├── reconx.py                # Main CLI & interactive entry point
├── requirements.txt
└── README.md
```

---

## 💻 Usage

### 1. Interactive Mode
Run without arguments for an interactive prompt:
```bash
python reconx.py
```
```text
Enter Target:
https://example.com

Enter Email:
admin@example.com
```

### 2. Direct Command-Line Mode
```bash
python reconx.py --target example.com --email admin@example.com
```

### 3. Professional PDF Download Mode (with Custom Company Name)
Download a cybersecurity audit report PDF with top company branding:
```bash
python reconx.py --target example.com --email admin@example.com --pdf reports/example_audit.pdf --company "CYBER DEFENSE INTELLIGENCE LABS"
```
Or simply use `--pdf` to auto-generate a timestamped PDF in `reports/`:
```bash
python reconx.py --target example.com --email admin@example.com --pdf
```

### 4. Machine-Readable JSON Output
```bash
python reconx.py --target example.com --email admin@example.com --json
```

---

## 🖥️ Sample Terminal Output

```text
==============================
          RECONX
==============================

TARGET: example.com

[DOMAIN]
IP Address       : 93.184.216.34
HTTPS            : Enabled
SSL              : Valid
Server           : nginx

[DNS]
A Record         : Found
MX Record        : Found
NS Record        : Found

[SUBDOMAINS]
www.example.com
mail.example.com
blog.example.com

[WEBSITE]
robots.txt       : Found
sitemap.xml      : Found
Security Headers : 5/7

[EMAIL]
Domain           : example.com
Format           : Valid
Public Exposure  : Found
Breach Check     : No Match

------------------------------
EXPOSURE SCORE: 24/100
LEVEL: LOW
------------------------------
```

---

## 🧪 Running Tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```
Ran 6 tests: `OK`.
