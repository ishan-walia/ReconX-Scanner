"""
Subdomain reconnaissance module.
Combines Certificate Transparency (crt.sh & Certspotter), HackerTarget API,
and rapid concurrent DNS resolution for deep discovery.
"""

import socket
import urllib.request
import json
import concurrent.futures
from typing import List, Set, Optional


COMMON_PREFIXES = [
    "www", "mail", "blog", "api", "dev", "admin",
    "vpn", "app", "portal", "test", "webmail", "cpanel",
    "secure", "shop", "support", "docs", "autodiscover",
    "ns1", "ns2", "ftp", "m", "remote", "server"
]


def _query_hackertarget(root_domain: str, timeout: int = 4) -> Set[str]:
    """Discover subdomains via HackerTarget hostsearch API."""
    subs: Set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                lines = resp.read().decode("utf-8", errors="ignore").splitlines()
                for line in lines:
                    parts = line.split(",")
                    if parts and parts[0].endswith(root_domain):
                        subs.add(parts[0].strip().lower())
    except Exception:
        pass
    return subs


def _query_certspotter(root_domain: str, timeout: int = 4) -> Set[str]:
    """Query Certspotter Certificate Transparency logs."""
    subs: Set[str] = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={root_domain}&include_subdomains=true&expand=dns_names"
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data[:15]:
                    for dns_name in entry.get("dns_names", []):
                        name = dns_name.strip().lower()
                        if "*" not in name and name.endswith(root_domain) and name != root_domain:
                            subs.add(name)
    except Exception:
        pass
    return subs


def _query_crtsh(root_domain: str, timeout: int = 4) -> Set[str]:
    """Query crt.sh Certificate Transparency logs."""
    subs: Set[str] = set()
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ReconX/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                for entry in data[:20]:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower()
                        if "*" not in sub and sub.endswith(root_domain) and sub != root_domain:
                            subs.add(sub)
    except Exception:
        pass
    return subs


def _check_dns(subdomain: str) -> Optional[str]:
    """Test if subdomain resolves to an IP address."""
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except Exception:
        return None


def discover_subdomains(root_domain: str, max_results: int = 20) -> List[str]:
    """
    Orchestrates CT logs, public API searches, and multi-threaded DNS brute resolution.
    """
    candidates: Set[str] = set()

    # 1. Query HackerTarget API
    candidates.update(_query_hackertarget(root_domain))

    # 2. Query Certspotter / crt.sh
    candidates.update(_query_certspotter(root_domain))
    if len(candidates) < 3:
        candidates.update(_query_crtsh(root_domain))

    # 3. Add common dictionary prefixes
    for prefix in COMMON_PREFIXES:
        candidates.add(f"{prefix}.{root_domain}")

    # 4. Resolve concurrently to verify which ones are active
    active: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(_check_dns, sub) for sub in candidates]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                active.append(res)

    # Sort prioritized: www first, then alphabetical
    active = list(set(active))
    active.sort(key=lambda s: (0 if s.startswith("www.") else 1, s))
    return active[:max_results]
