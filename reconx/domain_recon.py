"""
Domain, DNS, WHOIS & Geolocation reconnaissance module.
Performs IP resolution, GeoIP/ASN lookup, DNS record queries (A, MX, NS, TXT, SPF, DMARC),
and RDAP/WHOIS registrar analysis.
"""

import socket
import urllib.request
import urllib.parse
import json
import re
from typing import Dict, Any, List, Tuple


# Known multi-part TLD suffixes
MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.br", "co.nz", "co.za", "co.jp"
}


def normalize_domains(target: str) -> Tuple[str, str]:
    """
    Extracts both the specific target host and its apex/root registrar domain.
    Example: 'https://www.mkindustriesglobal.com/page'
             -> ('www.mkindustriesglobal.com', 'mkindustriesglobal.com')
             'https://api.dev.example.co.uk'
             -> ('api.dev.example.co.uk', 'example.co.uk')
    """
    target = target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        host = parsed.netloc
    else:
        host = target.split("/")[0]

    if ":" in host:
        host = host.split(":")[0]

    host = host.lower().strip()

    # Determine root domain
    parts = host.split(".")
    if len(parts) <= 2:
        root_domain = host
    else:
        # Check two-part TLD (e.g. example.co.uk)
        two_part = ".".join(parts[-2:])
        if two_part in MULTI_PART_TLDS and len(parts) >= 3:
            root_domain = ".".join(parts[-3:])
        else:
            root_domain = ".".join(parts[-2:])

    return host, root_domain


def extract_domain(target: str) -> str:
    """Convenience helper returning host domain."""
    host, root = normalize_domains(target)
    return host


def query_doh_record(domain: str, record_type: str, timeout: int = 5) -> List[str]:
    """
    Query DNS-over-HTTPS (Cloudflare DoH API) for cross-platform DNS resolution.
    """
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type={record_type}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/dns-json", "User-Agent": "ReconX/1.0"}
    )
    records = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                for answer in data.get("Answer", []):
                    data_val = answer.get("data", "").strip(' "')
                    if data_val:
                        records.append(data_val)
    except Exception:
        pass
    return records


def resolve_ip(domain: str) -> Dict[str, Any]:
    """Resolve IPv4 and IPv6 addresses using local socket."""
    ipv4_addresses = []
    ipv6_addresses = []

    try:
        infos = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if family == socket.AF_INET and ip not in ipv4_addresses:
                ipv4_addresses.append(ip)
            elif family == socket.AF_INET6 and ip not in ipv6_addresses:
                ipv6_addresses.append(ip)
    except Exception:
        pass

    primary_ip = ipv4_addresses[0] if ipv4_addresses else (ipv6_addresses[0] if ipv6_addresses else "Unknown")
    return {
        "primary_ip": primary_ip,
        "ipv4": ipv4_addresses,
        "ipv6": ipv6_addresses,
    }


def lookup_geoip(ip: str, timeout: int = 4) -> Dict[str, Any]:
    """
    Fetch IP Geolocation, ASN, and ISP details using public IP-API.
    """
    if not ip or ip in ("Unknown", "127.0.0.1", "0.0.0.0"):
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}

    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    return {
                        "country": f"{data.get('country', 'Unknown')} ({data.get('countryCode', '')})",
                        "city": f"{data.get('city', 'Unknown')}, {data.get('regionName', '')}".strip(", "),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                        "asn": data.get("as", "Unknown"),
                    }
    except Exception:
        pass

    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "asn": "Unknown"}


def query_rdap(root_domain: str, timeout: int = 6) -> Dict[str, Any]:
    """
    Query open RDAP for registrar, creation, expiry, and status of apex domain.
    """
    url = f"https://rdap.org/domain/{root_domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    result = {
        "registrar": "Not Disclosed",
        "created_date": "Unknown",
        "expires_date": "Unknown",
        "status": []
    }
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                # Registrar
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [[], []])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    result["registrar"] = item[3]
                                    break
                # Registration & Expiration Events
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    date_val = event.get("eventDate", "").split("T")[0]
                    if action == "registration":
                        result["created_date"] = date_val
                    elif action == "expiration":
                        result["expires_date"] = date_val

                status_list = data.get("status", [])
                result["status"] = [s.replace("prohibited", "").strip() for s in status_list[:3]]
    except Exception:
        pass
    return result


def analyze_domain(target: str) -> Dict[str, Any]:
    """
    Perform deep domain, DNS, GeoIP, and WHOIS reconnaissance.
    """
    host, root_domain = normalize_domains(target)
    
    # Resolve host IP (or root domain fallback)
    ip_info = resolve_ip(host)
    if ip_info["primary_ip"] == "Unknown" and host != root_domain:
        ip_info = resolve_ip(root_domain)

    # GeoIP & ISP Intelligence
    geoip_info = lookup_geoip(ip_info["primary_ip"])

    # DNS Records (Query host, fallback to root_domain)
    a_records = query_doh_record(host, "A") or query_doh_record(root_domain, "A") or ip_info["ipv4"]
    mx_records = query_doh_record(root_domain, "MX")
    ns_records = query_doh_record(root_domain, "NS")
    txt_records = query_doh_record(root_domain, "TXT")

    # SPF & DMARC Detection
    has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
    spf_record = next((txt for txt in txt_records if "v=spf1" in txt.lower()), None)
    
    dmarc_records = query_doh_record(f"_dmarc.{root_domain}", "TXT")
    has_dmarc = any("v=dmarc1" in txt.lower() for txt in dmarc_records)
    dmarc_record = next((txt for txt in dmarc_records if "v=dmarc1" in txt.lower()), None)

    # Check for Domain Parking signatures in NS
    is_parked = any("parking" in ns.lower() or "sedoparking" in ns.lower() for ns in ns_records)

    # RDAP WHOIS queried on apex root domain
    rdap_info = query_rdap(root_domain)

    return {
        "host": host,
        "root_domain": root_domain,
        "ip_info": ip_info,
        "geoip": geoip_info,
        "is_parked": is_parked,
        "dns": {
            "a": a_records,
            "mx": mx_records,
            "ns": ns_records,
            "txt": txt_records,
            "has_a": len(a_records) > 0,
            "has_mx": len(mx_records) > 0,
            "has_ns": len(ns_records) > 0,
            "has_spf": has_spf,
            "spf_record": spf_record,
            "has_dmarc": has_dmarc,
            "dmarc_record": dmarc_record,
        },
        "whois": rdap_info
    }
