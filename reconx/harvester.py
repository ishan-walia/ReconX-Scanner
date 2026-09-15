"""
Passive OSINT Harvester Module (theHarvester-style engine).
Harvests public emails, hostnames, IP mappings, and employee/user contacts
from public registers, RDAP, web endpoints, and Certificate Transparency logs.
"""

import re
import socket
import urllib.request
import urllib.parse
import json
from typing import Dict, Any, List, Set, Tuple


EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

COMMON_ROLES = [
    "admin", "security", "info", "contact", "support",
    "sales", "compliance", "abuse", "postmaster", "webmaster"
]


def _harvest_web_emails(domain: str, root_domain: str, timeout: float = 3.0) -> List[Dict[str, str]]:
    """
    Passively inspects standard public web endpoints (homepage, /contact, /about, /security.txt)
    for publicly exposed email addresses.
    """
    discovered: List[Dict[str, str]] = []
    seen: Set[str] = set()

    paths = ["/", "/contact", "/about", "/.well-known/security.txt", "/security.txt"]
    proto = "https"

    for path in paths:
        url = f"{proto}://{domain}{path}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconX/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get("Content-Type", "").lower()
                    if "text" in content_type or "json" in content_type:
                        body = resp.read().decode("utf-8", errors="ignore")
                        matches = EMAIL_REGEX.findall(body)
                        for match in matches:
                            clean = match.lower().strip(".,;:\"'()<>")
                            # Only keep emails ending in root_domain or related
                            if root_domain in clean and clean not in seen:
                                seen.add(clean)
                                discovered.append({
                                    "email": clean,
                                    "source": f"Web Endpoint ({path})"
                                })
        except Exception:
            continue

    return discovered


def _harvest_rdap_contacts(root_domain: str, timeout: float = 4.0) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Harvests technical, abuse, and administrative contact emails and names
    from open RDAP registry records.
    """
    emails: List[Dict[str, str]] = []
    users: List[str] = []
    seen: Set[str] = set()

    url = f"https://rdap.org/domain/{root_domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                entities = data.get("entities", [])
                
                # Recursive entity traverser
                def parse_entities(ents):
                    for ent in ents:
                        roles = ", ".join(ent.get("roles", [])) or "Contact"
                        vcard = ent.get("vcardArray", [[], []])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "email" and len(item) > 3:
                                    e = item[3].strip().lower()
                                    if e and e not in seen:
                                        seen.add(e)
                                        emails.append({
                                            "email": e,
                                            "source": f"RDAP WHOIS ({roles.title()})"
                                        })
                                elif item[0] == "fn" and len(item) > 3:
                                    fn = item[3].strip()
                                    if fn and fn not in users and "privacy" not in fn.lower() and "protect" not in fn.lower():
                                        users.append(fn)
                        if ent.get("entities"):
                            parse_entities(ent.get("entities"))

                parse_entities(entities)
    except Exception:
        pass

    return emails, users


def _harvest_cert_emails(root_domain: str, timeout: float = 4.0) -> List[Dict[str, str]]:
    """
    Extracts administrator/technical contact emails from Certificate Transparency logs.
    """
    emails: List[Dict[str, str]] = []
    seen: Set[str] = set()

    url = f"https://api.certspotter.com/v1/issuances?domain={root_domain}&include_subdomains=true&expand=dns_names"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data[:10]:
                    txt = json.dumps(entry)
                    for match in EMAIL_REGEX.findall(txt):
                        clean = match.lower().strip(".,;:\"'()<>")
                        if root_domain in clean and clean not in seen:
                            seen.add(clean)
                            emails.append({
                                "email": clean,
                                "source": "Certificate Transparency Log"
                            })
    except Exception:
        pass

    return emails


def _harvest_role_accounts(root_domain: str, has_mx: bool) -> List[Dict[str, str]]:
    """
    Identifies high-value RFC standard mailboxes if the target has active MX routing.
    """
    if not has_mx:
        return []

    return [
        {"email": f"security@{root_domain}", "source": "Standard RFC 9116 Mailbox"},
        {"email": f"abuse@{root_domain}", "source": "Standard RFC 2142 Mailbox"},
    ]


def run_harvester(
    target_domain: str,
    root_domain: str,
    has_mx: bool = True,
    subdomain_list: List[str] = None
) -> Dict[str, Any]:
    """
    Execute comprehensive theHarvester-style passive OSINT pipeline:
    - Public Email Addresses
    - Discovered Hosts with IP Resolution
    - Registered Contacts / Personnel
    """
    harvested_emails: List[Dict[str, str]] = []
    seen_emails: Set[str] = set()

    # 1. Public Web Endpoints
    for item in _harvest_web_emails(target_domain, root_domain):
        if item["email"] not in seen_emails:
            seen_emails.add(item["email"])
            harvested_emails.append(item)

    # 2. RDAP & Registry Contacts
    rdap_emails, users = _harvest_rdap_contacts(root_domain)
    for item in rdap_emails:
        if item["email"] not in seen_emails:
            seen_emails.add(item["email"])
            harvested_emails.append(item)

    # 3. Certificate Transparency Emails
    for item in _harvest_cert_emails(root_domain):
        if item["email"] not in seen_emails:
            seen_emails.add(item["email"])
            harvested_emails.append(item)

    # 4. Standard RFC Security Roles
    for item in _harvest_role_accounts(root_domain, has_mx):
        if item["email"] not in seen_emails:
            seen_emails.add(item["email"])
            harvested_emails.append(item)

    # 5. Hosts & IP Mappings from Subdomains
    hosts: List[Dict[str, str]] = []
    if subdomain_list:
        for sub in subdomain_list[:10]:
            try:
                ip = socket.gethostbyname(sub)
                hosts.append({"host": sub, "ip": ip})
            except Exception:
                hosts.append({"host": sub, "ip": "Unresolved"})

    return {
        "engine": "ReconX Passive theHarvester OSINT Engine",
        "target": target_domain,
        "root_domain": root_domain,
        "emails": harvested_emails,
        "total_emails": len(harvested_emails),
        "hosts": hosts,
        "total_hosts": len(hosts),
        "users": users,
        "total_users": len(users),
    }
