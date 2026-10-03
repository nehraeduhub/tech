"""Built-in lightweight TCP connect scan.

Attempts a plain TCP connection to a small set of common ports. This is a
connect scan (no raw packets, no SYN tricks) and does not send any payload --
it only records whether the port accepts a connection. Acts as a portable
fallback when nmap is not installed on the host.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from ..models import Finding

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Ports that are concerning if directly exposed to the internet.
RISKY = {23: "Telnet (cleartext)", 3389: "RDP", 445: "SMB", 3306: "MySQL",
         5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
         27017: "MongoDB"}


def _probe(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def run(url: str, result, timeout: float = 2.0) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    result.mark_check("TCP port scan (built-in)")
    result.log(f"Probing {len(COMMON_PORTS)} common TCP ports on {host}")

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_probe, host, p, timeout): p for p in COMMON_PORTS}
        for fut, port in futures.items():
            if fut.result():
                open_ports.append(port)

    open_ports.sort()
    if not open_ports:
        return
    result.meta["open_ports"] = {p: COMMON_PORTS[p] for p in open_ports}

    exposed_risky = [(p, RISKY[p]) for p in open_ports if p in RISKY]
    if exposed_risky:
        detail = ", ".join(f"{p}/{desc}" for p, desc in exposed_risky)
        result.add(Finding(
            title="Sensitive service ports exposed to the internet",
            severity="high", cwe="CWE-668: Exposure of Resource to Wrong Sphere",
            category="A05: Security Misconfiguration",
            description="Administrative or database service ports are reachable "
                        "from the internet.",
            impact="Directly exposed management/database services are prime targets "
                   "for brute force and known-exploit attacks.",
            evidence=f"Open risky ports: {detail}",
            recommendation="Restrict these ports with a firewall/VPN; never expose "
                           "databases or management interfaces publicly.",
            attack_surface=["Brute force", "Service-specific exploitation"],
            affected=host, confidence="High", check="ports",
        ))

    # Informational summary of all open ports.
    result.add(Finding(
        title="Open network ports discovered",
        severity="info", category="A05: Security Misconfiguration",
        description="A connect scan identified listening TCP ports. Confirm each "
                    "is intended to be internet-facing and kept patched.",
        impact="Each open port adds to the externally reachable attack surface.",
        evidence="; ".join(f"{p}/{COMMON_PORTS[p]}" for p in open_ports),
        recommendation="Close or firewall unnecessary ports; keep exposed services "
                       "patched and monitored.",
        attack_surface=["Attack surface growth"], affected=host, check="ports",
    ))
