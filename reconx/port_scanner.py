"""
Fast multi-threaded port and service scanner module for ReconX.
Audits the most common TCP service ports safely and rapidly.
"""

import socket
import concurrent.futures
from typing import Dict, List, Tuple


COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (465, "SMTPS"),
    (587, "Submission"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (2082, "cPanel"),
    (2083, "cPanel-SSL"),
    (2086, "WHM"),
    (2087, "WHM-SSL"),
    (3306, "MySQL"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
]


def _check_port(ip: str, port: int, service: str, timeout: float = 0.8) -> Tuple[int, str, bool]:
    """Test connection to a single TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((ip, port))
            return (port, service, res == 0)
    except Exception:
        return (port, service, False)


def scan_ports(ip: str, max_workers: int = 20) -> Dict[str, Any]:
    """
    Rapidly scans common ports on target IP using thread pool.
    """
    if not ip or ip in ("Unknown", "127.0.0.1", "0.0.0.0"):
        return {"open_ports": [], "summary": "Unresolvable IP"}

    open_ports: List[Dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_check_port, ip, port, service) for port, service in COMMON_PORTS]
        for f in concurrent.futures.as_completed(futures):
            port, service, is_open = f.result()
            if is_open:
                open_ports.append({"port": port, "service": service})

    open_ports.sort(key=lambda x: x["port"])
    summary = ", ".join([f"{p['port']} ({p['service']})" for p in open_ports]) if open_ports else "None (Filtered or Stealth)"

    return {
        "open_ports": open_ports,
        "count": len(open_ports),
        "summary": summary
    }
