"""Passive TLS/SSL inspection.

Opens a TLS connection and reads the certificate and negotiated protocol.
It does not attempt downgrade attacks or exploit anything -- it inspects what
the server presents, which is standard assessment practice.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..models import Finding

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def run(url: str, result, timeout: int = 15) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return

    result.log(f"Inspecting TLS certificate for {host}:{port}")
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                result.meta["tls_version"] = proto
                _check_protocol(proto, result)
                _check_cert(cert, host, result)
    except ssl.SSLCertVerificationError as exc:
        result.add(Finding(
            title="TLS certificate validation failed",
            severity="high",
            category="A02: Cryptographic Failures",
            description="The server's certificate could not be validated against "
                        "trusted roots (expired, self-signed, or wrong host).",
            evidence=str(exc),
            recommendation="Install a valid certificate from a trusted CA that "
                           "matches the hostname.",
            attack_surface=["Man-in-the-middle", "Trust warnings deter users"],
            check="tls",
        ))
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"TLS check failed: {exc}")


def _check_protocol(proto: str | None, result) -> None:
    if proto and proto in WEAK_PROTOCOLS:
        result.add(Finding(
            title=f"Weak TLS protocol negotiated: {proto}",
            severity="high",
            category="A02: Cryptographic Failures",
            description="The connection negotiated an outdated TLS/SSL version "
                        "with known weaknesses.",
            evidence=f"Negotiated protocol: {proto}",
            recommendation="Disable TLS 1.1 and below; require TLS 1.2+ (prefer 1.3).",
            attack_surface=["Protocol downgrade", "Cipher attacks"],
            check="tls",
        ))


def _check_cert(cert: dict, host: str, result) -> None:
    if not cert:
        return
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (expires - datetime.now(timezone.utc)).days
            result.meta["cert_expires"] = not_after
            result.meta["cert_days_left"] = days
            if days < 0:
                sev, title = "high", "TLS certificate has expired"
            elif days < 15:
                sev, title = "medium", "TLS certificate expiring very soon"
            elif days < 30:
                sev, title = "low", "TLS certificate expiring within 30 days"
            else:
                sev = None
                title = ""
            if sev:
                result.add(Finding(
                    title=title,
                    severity=sev,
                    category="A02: Cryptographic Failures",
                    description="Certificate expiry affects trust and availability.",
                    evidence=f"notAfter: {not_after} ({days} days remaining)",
                    recommendation="Renew the certificate and automate renewal.",
                    attack_surface=["Service trust warnings", "MITM if ignored"],
                    check="tls",
                ))
        except ValueError:
            pass
