"""CORS misconfiguration check (reflective, non-intrusive).

Sends a single GET with a crafted Origin header and inspects the
Access-Control-Allow-Origin response. This only reads how the server reacts;
it does not attack anything.
"""
from __future__ import annotations

import requests

from ..models import Finding

UA = "RJHex-VAPT/2.0 (authorised security assessment)"
TEST_ORIGIN = "https://rjhex-cors-probe.example"


def run(url: str, result, timeout: int = 15) -> None:
    result.mark_check("CORS policy")
    try:
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, verify=True,
            headers={"User-Agent": UA, "Origin": TEST_ORIGIN},
        )
    except Exception:  # noqa: BLE001
        return

    h = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        result.add(Finding(
            title="Insecure CORS: wildcard origin with credentials",
            severity="high", cwe="CWE-942: Permissive Cross-domain Policy",
            category="A05: Security Misconfiguration",
            description="The server returns Access-Control-Allow-Origin: * together "
                        "with Allow-Credentials: true, an invalid and dangerous "
                        "combination.",
            impact="Any origin could read authenticated responses on behalf of a "
                   "logged-in user.",
            evidence=f"ACAO: {acao}; ACAC: {acac}",
            recommendation="Never combine a wildcard origin with credentials; "
                           "echo only an explicit allow-list of trusted origins.",
            attack_surface=["Cross-origin data theft"], affected=resp.url,
            confidence="High", check="cors",
        ))
    elif acao == TEST_ORIGIN:
        sev = "high" if acac == "true" else "medium"
        result.add(Finding(
            title="Insecure CORS: arbitrary origin reflected",
            severity=sev, cwe="CWE-942: Permissive Cross-domain Policy",
            category="A05: Security Misconfiguration",
            description="The server reflects an arbitrary Origin back in "
                        "Access-Control-Allow-Origin, trusting any site.",
            impact="A malicious site can make cross-origin requests that the "
                   "browser will allow to read responses"
                   + (" with credentials." if acac == "true" else "."),
            evidence=f"Sent Origin: {TEST_ORIGIN} -> ACAO: {acao}; ACAC: {acac}",
            recommendation="Validate Origin against a strict server-side allow-list "
                           "instead of reflecting it.",
            attack_surface=["Cross-origin data theft", "CSRF amplification"],
            affected=resp.url, check="cors",
        ))
