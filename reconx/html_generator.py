"""
HTML Report Generator for ReconX.
Creates a modern, responsive, cyber-dark interactive executive audit report.
"""

import html
from datetime import datetime, timezone
from typing import Dict, Any


def generate_html_report(
    report_data: Dict[str, Any],
    output_path: str,
    company_name: str = "CYBER DEFENSE INTELLIGENCE LABS"
) -> str:
    """
    Builds and writes a single-file, self-contained HTML executive report.
    """
    target = html.escape(str(report_data.get("target", "Unknown")))
    root_domain = html.escape(str(report_data.get("root_domain", "")))
    domain_data = report_data.get("domain", {})
    port_data = report_data.get("ports", {})
    website_data = report_data.get("website", {})
    subdomains = report_data.get("subdomains", [])
    email_data = report_data.get("email")
    exposure = report_data.get("exposure", {})

    ssl_info = website_data.get("ssl", {})
    web_info = website_data.get("web", {})
    dns_info = domain_data.get("dns", {})
    whois_info = domain_data.get("whois", {})
    geoip = domain_data.get("geoip", {})

    score = exposure.get("score", 0)
    level = exposure.get("level", "LOW")
    findings = exposure.get("findings", [])
    recommendations = exposure.get("recommendations", [])

    # Status badge color
    if level == "HIGH":
        badge_color = "#ef4444"
        badge_bg = "rgba(239, 68, 68, 0.15)"
    elif level == "MEDIUM":
        badge_color = "#f59e0b"
        badge_bg = "rgba(245, 158, 11, 0.15)"
    else:
        badge_color = "#10b981"
        badge_bg = "rgba(16, 185, 129, 0.15)"

    waf = web_info.get("waf_detected", "None Detected")
    security_txt = "Available (RFC 9116)" if web_info.get("security_txt_found") else "Not Disclosed"
    dnssec = "Enabled (DS Active)" if dns_info.get("has_dnssec") else "Not Active"
    caa = "Configured" if dns_info.get("has_caa") else "None Disclosed"

    # Present headers
    present_headers_html = "".join(
        f"<tr><td><code>{html.escape(h[0])}</code></td><td class='val-truncate'>{html.escape(str(h[1]))}</td><td><span class='badge-pass'>PASS</span></td></tr>"
        for h in web_info.get("present_headers", [])
    ) or "<tr><td colspan='3' class='muted'>No defensive headers detected</td></tr>"

    # Missing headers
    missing_headers_html = "".join(
        f"<tr><td><code>{html.escape(h[0])}</code></td><td>{html.escape(str(h[1]))}</td><td><span class='badge-fail'>MISSING</span></td></tr>"
        for h in web_info.get("missing_headers", [])
    ) or "<tr><td colspan='3' class='muted'>All monitored security headers are configured!</td></tr>"

    # Subdomains list
    subdomains_html = "".join(
        f"<li><span class='bullet-dot'></span>{html.escape(sub)}</li>"
        for sub in subdomains
    ) or "<li class='muted'>No subdomains discovered via CT logs.</li>"

    # Findings
    findings_html = "".join(
        f"<div class='alert-card alert-risk'><div class='alert-icon'>⚠️</div><div>{html.escape(f)}</div></div>"
        for f in findings
    )

    # Recommendations
    recs_html = "".join(
        f"<div class='alert-card alert-rec'><div class='alert-icon'>🛡️</div><div>{html.escape(r)}</div></div>"
        for r in recommendations
    ) or "<div class='alert-card alert-rec'><div class='alert-icon'>✅</div><div>Maintain regular patch hygiene and periodic scans.</div></div>"

    # theHarvester Intelligence
    harvester_data = report_data.get("harvester", {})
    harvested_emails = harvester_data.get("emails", [])
    harvested_users = harvester_data.get("users", [])

    harvested_emails_html = "".join(
        f"<tr><td><code>{html.escape(item['email'])}</code></td><td>{html.escape(item.get('source', 'OSINT'))}</td><td><span class='badge-pass'>DISCOVERED</span></td></tr>"
        for item in harvested_emails
    ) or "<tr><td colspan='3' class='muted'>No public email footprints harvested.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ReconX Executive Report - {target}</title>
  <style>
    :root {{
      --bg-dark: #0b0f19;
      --card-bg: #131b2e;
      --card-border: #1f2d48;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-purple: #a855f7;
      --risk-low: #10b981;
      --risk-med: #f59e0b;
      --risk-high: #ef4444;
      --font-mono: "Fira Code", monospace, "SF Mono", Menlo, Consolas;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg-dark);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 20px 24px;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      margin-bottom: 24px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand h1 {{
      font-size: 20px;
      letter-spacing: 0.5px;
      color: #fff;
    }}
    .tag {{
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent-blue);
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }}
    .timestamp {{
      color: var(--text-muted);
      font-size: 13px;
    }}
    /* Score Banner */
    .score-banner {{
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
      background: linear-gradient(135deg, #131b2e 0%, #17223b 100%);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }}
    .target-info h2 {{
      font-size: 26px;
      font-family: var(--font-mono);
      color: #fff;
      margin-bottom: 6px;
    }}
    .target-meta {{
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 16px;
    }}
    .score-box {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      border-left: 1px solid var(--card-border);
      padding-left: 20px;
    }}
    .score-number {{
      font-size: 52px;
      font-weight: 800;
      color: {badge_color};
      line-height: 1;
    }}
    .score-label {{
      font-size: 12px;
      letter-spacing: 1px;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-top: 4px;
    }}
    .level-badge {{
      margin-top: 10px;
      background: {badge_bg};
      color: {badge_color};
      border: 1px solid {badge_color};
      padding: 4px 16px;
      border-radius: 20px;
      font-weight: 700;
      font-size: 13px;
    }}
    /* Section grid */
    .grid-2 {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
      margin-bottom: 24px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
    }}
    .card h3 {{
      font-size: 15px;
      letter-spacing: 0.5px;
      color: var(--accent-blue);
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .prop-list {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .prop-item {{
      display: flex;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      padding-bottom: 6px;
      font-size: 13px;
    }}
    .prop-name {{
      color: var(--text-muted);
    }}
    .prop-val {{
      font-family: var(--font-mono);
      color: #fff;
      text-align: right;
    }}
    /* Tables */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 8px;
    }}
    th, td {{
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }}
    th {{
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    td code {{
      font-family: var(--font-mono);
      color: var(--accent-blue);
    }}
    .val-truncate {{
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .badge-pass {{
      background: rgba(16, 185, 129, 0.15);
      color: var(--risk-low);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }}
    .badge-fail {{
      background: rgba(239, 68, 68, 0.15);
      color: var(--risk-high);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }}
    /* Subdomains */
    .subdomain-grid {{
      list-style: none;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }}
    .subdomain-grid li {{
      background: rgba(255,255,255,0.03);
      padding: 6px 10px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #cbd5e1;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .bullet-dot {{
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-blue);
    }}
    /* Findings & Recommendations */
    .alert-card {{
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 10px;
    }}
    .alert-risk {{
      background: rgba(239, 68, 68, 0.08);
      border-left: 4px solid var(--risk-high);
      color: #fca5a5;
    }}
    .alert-rec {{
      background: rgba(16, 185, 129, 0.08);
      border-left: 4px solid var(--risk-low);
      color: #86efac;
    }}
    .alert-icon {{
      font-size: 16px;
    }}
    .muted {{
      color: var(--text-muted);
      font-style: italic;
    }}
    footer {{
      margin-top: 32px;
      text-align: center;
      color: var(--text-muted);
      font-size: 12px;
      border-top: 1px solid var(--card-border);
      padding-top: 16px;
    }}
    @media (max-width: 768px) {{
      .score-banner, .grid-2 {{
        grid-template-columns: 1fr;
      }}
      .score-box {{
        border-left: none;
        border-top: 1px solid var(--card-border);
        padding-left: 0;
        padding-top: 16px;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>{company_name}</h1>
        <span class="tag">RECONX AUDIT</span>
      </div>
      <div class="timestamp">
        Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if 'timezone' in globals() else datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
      </div>
    </header>

    <div class="score-banner">
      <div class="target-info">
        <h2>{target}</h2>
        <div class="target-meta">Apex Domain: {root_domain} &bull; Classification: Passive Public Reconnaissance</div>
        <p style="font-size: 14px; color: #cbd5e1;">
          Non-invasive attack surface map assessing DNS, WHOIS, SSL/TLS, reverse-proxy WAF configurations, open service ports, and email security posture.
        </p>
      </div>
      <div class="score-box">
        <div class="score-number">{score}</div>
        <div class="score-label">Exposure Score (0-100)</div>
        <div class="level-badge">{level} RISK</div>
      </div>
    </div>

    <!-- Grid 1: Infrastructure & WHOIS -->
    <div class="grid-2">
      <div class="card">
        <h3>🌐 Infrastructure & Geolocation</h3>
        <div class="prop-list">
          <div class="prop-item"><span class="prop-name">Primary IP</span><span class="prop-val">{domain_data.get('ip_info', {}).get('primary_ip', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">Location</span><span class="prop-val">{geoip.get('city', '')}, {geoip.get('country', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">ISP / Network</span><span class="prop-val">{geoip.get('isp', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">ASN</span><span class="prop-val">{geoip.get('asn', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">WAF / CDN</span><span class="prop-val">{waf}</span></div>
          <div class="prop-item"><span class="prop-name">Open Ports</span><span class="prop-val">{port_data.get('summary', 'None')}</span></div>
        </div>
      </div>

      <div class="card">
        <h3>📋 Registrar & DNS Security</h3>
        <div class="prop-list">
          <div class="prop-item"><span class="prop-name">Registrar</span><span class="prop-val">{whois_info.get('registrar', 'Not Disclosed')}</span></div>
          <div class="prop-item"><span class="prop-name">Creation Date</span><span class="prop-val">{whois_info.get('created_date', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">SPF Record</span><span class="prop-val">{'PASS' if dns_info.get('has_spf') else 'MISSING'}</span></div>
          <div class="prop-item"><span class="prop-name">DMARC Record</span><span class="prop-val">{'PASS' if dns_info.get('has_dmarc') else 'MISSING'}</span></div>
          <div class="prop-item"><span class="prop-name">DNSSEC</span><span class="prop-val">{dnssec}</span></div>
          <div class="prop-item"><span class="prop-name">CAA Policy</span><span class="prop-val">{caa}</span></div>
          <div class="prop-item"><span class="prop-name">security.txt</span><span class="prop-val">{security_txt}</span></div>
        </div>
      </div>
    </div>

    <!-- Grid 2: SSL & Web Details -->
    <div class="grid-2">
      <div class="card">
        <h3>🔒 Cryptographic SSL/TLS Posture</h3>
        <div class="prop-list">
          <div class="prop-item"><span class="prop-name">SSL Status</span><span class="prop-val">{ssl_info.get('ssl_status', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">Issuer</span><span class="prop-val">{ssl_info.get('issuer', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">Expires On</span><span class="prop-val">{ssl_info.get('expires_on', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">Days Remaining</span><span class="prop-val">{ssl_info.get('days_remaining', 'Unknown')}</span></div>
          <div class="prop-item"><span class="prop-name">HTTPS Enforced</span><span class="prop-val">{'Yes' if web_info.get('https_enabled') else 'No'}</span></div>
          <div class="prop-item"><span class="prop-name">Server Banner</span><span class="prop-val">{web_info.get('server_banner', 'Not Disclosed')}</span></div>
        </div>
      </div>

      <div class="card">
        <h3>🔍 Discovered Subdomains ({len(subdomains)})</h3>
        <ul class="subdomain-grid">
          {subdomains_html}
        </ul>
      </div>
    </div>

    <!-- Security Headers Table -->
    <div class="card" style="margin-bottom: 24px;">
      <h3>🛡️ OWASP Defensive HTTP Headers ({web_info.get('headers_score_str', '0/7')})</h3>
      <table>
        <thead>
          <tr>
            <th style="width: 30%;">Header</th>
            <th style="width: 55%;">Value / Description</th>
            <th style="width: 15%;">Status</th>
          </tr>
        </thead>
        <tbody>
          {present_headers_html}
          {missing_headers_html}
        </tbody>
      </table>
    </div>

    <!-- theHarvester OSINT Intelligence Table -->
    <div class="card" style="margin-bottom: 24px;">
      <h3>🎯 Passive theHarvester OSINT Intelligence ({len(harvested_emails)} Public Footprints)</h3>
      <table>
        <thead>
          <tr>
            <th style="width: 45%;">Discovered Email / Identity</th>
            <th style="width: 40%;">Source / Detection Method</th>
            <th style="width: 15%;">Status</th>
          </tr>
        </thead>
        <tbody>
          {harvested_emails_html}
        </tbody>
      </table>
    </div>

    <!-- Findings & Recommendations -->
    <div class="grid-2">
      <div class="card">
        <h3>⚠️ Identified Exposure Findings</h3>
        {findings_html}
      </div>

      <div class="card">
        <h3>💡 Prioritized Remediation Advice</h3>
        {recs_html}
      </div>
    </div>

    <footer>
      Generated by <b>ReconX</b> &bull; Authorized Penetration Testing & Defensive Hardening Utility
    </footer>
  </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
