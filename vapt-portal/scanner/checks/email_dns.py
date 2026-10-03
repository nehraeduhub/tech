"""DNS posture and email-security checks (SPF, DMARC, DKIM, DNSSEC, CAA).

Read-only DNS queries. No zone transfers are performed. Provides both
contextual records for the report and findings for missing email-spoofing
protections -- a standard part of a professional assessment.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import Finding

try:
    import dns.resolver  # type: ignore
    import dns.name  # type: ignore
    _HAVE_DNS = True
except Exception:  # noqa: BLE001
    _HAVE_DNS = False

COMMON_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail")


def _resolve(name: str, rtype: str):
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=8)]
    except Exception:  # noqa: BLE001
        return []


def run(url: str, result) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    result.mark_check("DNS & email security")
    if not _HAVE_DNS:
        result.log("dnspython not installed; skipping DNS checks")
        return

    # Reduce to the registrable domain for TXT/DMARC/CAA where sensible.
    root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    result.log(f"Resolving DNS records for {host}")

    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        vals = _resolve(host, rtype)
        if vals:
            records[rtype] = vals
    result.meta["dns_records"] = records

    txt = " ".join(_resolve(root, "TXT") + records.get("TXT", []))

    # --- SPF ---
    if "v=spf1" not in txt.lower():
        result.add(Finding(
            title="No SPF record published",
            severity="low", cwe="CWE-290: Authentication Bypass by Spoofing",
            category="A07: Identification & Authentication Failures",
            description="No SPF TXT record was found for the domain, making email "
                        "spoofing of this domain easier.",
            impact="Attackers can send spoofed email appearing to come from the "
                   "domain (phishing).",
            evidence=f"TXT at {root}: {_resolve(root, 'TXT') or 'none'}",
            recommendation="Publish an SPF record restricting authorised senders, "
                           "ending in '-all'.",
            attack_surface=["Email spoofing / phishing"], affected=root,
            check="email_dns",
        ))

    # --- DMARC ---
    dmarc = _resolve(f"_dmarc.{root}", "TXT")
    if not any("v=dmarc1" in d.lower() for d in dmarc):
        result.add(Finding(
            title="No DMARC record published",
            severity="low", cwe="CWE-290: Authentication Bypass by Spoofing",
            category="A07: Identification & Authentication Failures",
            description="No DMARC policy was found; receivers have no instruction "
                        "on handling unauthenticated mail from the domain.",
            impact="Reduces protection against spoofing and provides no visibility "
                   "via aggregate reports.",
            evidence=f"_dmarc.{root} TXT: {dmarc or 'none'}",
            recommendation="Publish a DMARC record, moving toward p=reject after "
                           "monitoring.",
            attack_surface=["Email spoofing / phishing"], affected=root,
            check="email_dns",
        ))
    elif any("p=none" in d.lower() for d in dmarc):
        result.add(Finding(
            title="DMARC policy is monitor-only (p=none)",
            severity="info", category="A07: Identification & Authentication Failures",
            description="A DMARC record exists but the policy is p=none, which "
                        "does not block spoofed mail.",
            impact="Spoofed mail is still delivered; DMARC is only reporting.",
            evidence=f"_dmarc.{root} TXT: {dmarc}",
            recommendation="After reviewing reports, move the policy to "
                           "quarantine then reject.",
            affected=root, check="email_dns",
        ))

    # --- DKIM (selector probe) ---
    found_dkim = [s for s in COMMON_DKIM_SELECTORS
                  if _resolve(f"{s}._domainkey.{root}", "TXT")]
    if not found_dkim:
        result.add(Finding(
            title="No common DKIM selector found",
            severity="info", category="A07: Identification & Authentication Failures",
            description="None of the common DKIM selectors resolved. DKIM may use a "
                        "custom selector, or email signing may be absent.",
            impact="Without DKIM, recipients cannot cryptographically verify mail "
                   "from the domain.",
            evidence=f"Checked selectors: {', '.join(COMMON_DKIM_SELECTORS)}",
            recommendation="Enable DKIM signing and publish the selector key.",
            affected=root, check="email_dns",
        ))

    # --- CAA ---
    if not records.get("CAA"):
        result.add(Finding(
            title="No CAA record published",
            severity="info", cwe="CWE-295: Improper Certificate Validation",
            category="A05: Security Misconfiguration",
            description="No Certification Authority Authorization record restricts "
                        "which CAs may issue certificates for the domain.",
            impact="Any CA may issue a certificate, slightly widening mis-issuance "
                   "risk.",
            evidence="No CAA records returned.",
            recommendation="Publish a CAA record naming your authorised CA(s).",
            affected=host, check="email_dns",
        ))

    # --- DNSSEC (best-effort) ---
    try:
        import dns.flags  # type: ignore
        ans = dns.resolver.resolve(host, "A", want_dnssec=True, lifetime=8)
        if not (ans.response.flags & dns.flags.AD):
            result.meta["dnssec"] = "not validated"
    except Exception:  # noqa: BLE001
        pass
