"""Passive WAF / CDN detection via response headers and cookies.

Read-only: inspects headers of a normal GET. Reported as informational context
for the assessment (a WAF is a positive control, its absence is noted neutrally).
"""
from __future__ import annotations

import requests

from ..models import Finding

UA = "RJHex-VAPT/2.0 (authorised security assessment)"

SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "akamai": ["akamai", "akamaighost", "x-akamai"],
    "aws": ["awselb", "x-amz-cf-id", "x-amzn-"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "imperva/incapsula": ["incap_ses", "x-iinfo", "incapsula"],
    "f5 big-ip": ["bigip", "x-waf-event", "ts01"],
    "fastly": ["x-served-by", "fastly"],
    "barracuda": ["barra"],
}


def run(url: str, result, timeout: int = 15) -> None:
    result.mark_check("WAF / CDN detection")
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            verify=True, headers={"User-Agent": UA})
    except Exception:  # noqa: BLE001
        return

    blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
    blob += " " + " ".join(resp.cookies.keys()).lower()
    server = resp.headers.get("Server", "").lower()

    detected = [name for name, sigs in SIGNATURES.items()
                if any(s in blob or s in server for s in sigs)]

    if detected:
        result.meta["waf"] = detected
        result.add(Finding(
            title=f"Web Application Firewall / CDN detected: {', '.join(detected)}",
            severity="info", category="Defensive Control (positive)",
            description="A WAF/CDN was fingerprinted from response metadata. This "
                        "is a defensive control, recorded for context.",
            impact="A WAF reduces (but does not eliminate) exposure to automated "
                   "attacks.",
            evidence=f"Signatures matched for: {', '.join(detected)}",
            recommendation="Keep WAF rule sets current; do not rely on a WAF as the "
                           "sole control.",
            affected=resp.url, check="waf",
        ))
    else:
        result.meta["waf"] = []
        result.add(Finding(
            title="No Web Application Firewall detected",
            severity="info", category="A05: Security Misconfiguration",
            description="No common WAF/CDN signature was observed in responses.",
            impact="Without a WAF the application is more exposed to automated "
                   "attacks and bots.",
            evidence="No WAF/CDN signatures matched known vendors.",
            recommendation="Consider deploying a WAF (e.g. ModSecurity + OWASP CRS) "
                           "as a defence-in-depth layer.",
            affected=resp.url, check="waf",
        ))
