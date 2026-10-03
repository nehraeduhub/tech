"""Passive DNS enumeration (resolution + record lookup).

Read-only DNS queries. No zone transfers are attempted by default and nothing
is written. Purely contextual information for the report.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding

try:
    import dns.resolver  # type: ignore
    _HAVE_DNS = True
except Exception:  # noqa: BLE001
    _HAVE_DNS = False


def run(url: str, result) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    if not _HAVE_DNS:
        result.log("dnspython not installed; skipping DNS record lookup")
        return

    result.log(f"Resolving DNS records for {host}")
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=8)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:  # noqa: BLE001
            continue
    result.meta["dns_records"] = records

    # SPF / DMARC presence (email spoofing context).
    txt = " ".join(records.get("TXT", []))
    if "v=spf1" not in txt.lower():
        result.add(Finding(
            title="No SPF record found",
            severity="low",
            category="A05: Security Misconfiguration",
            description="No SPF TXT record was found for the domain, which makes "
                        "email spoofing of this domain easier.",
            evidence=f"TXT records: {records.get('TXT', []) or 'none'}",
            recommendation="Publish an SPF record restricting which hosts may send "
                           "mail for the domain.",
            attack_surface=["Email spoofing / phishing"],
            check="dns_info",
        ))
