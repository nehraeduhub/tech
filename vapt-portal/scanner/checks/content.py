"""Passive content analysis of the landing page.

Fetches the home page once and inspects the returned HTML for mixed content,
software/CMS fingerprints, outdated JavaScript libraries, and forms that lack
CSRF protection. Purely read-only parsing of markup the server already sent.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from ..models import Finding

UA = "Tech Guardians-VAPT/2.0 (authorised security assessment)"

# Very small signature set of common libraries + a 'known old' heuristic.
LIB_PATTERNS = {
    "jquery": re.compile(r"jquery[-.](\d+\.\d+\.\d+)", re.I),
    "bootstrap": re.compile(r"bootstrap[-.](\d+\.\d+\.\d+)", re.I),
    "angular": re.compile(r"angular[-.](\d+\.\d+\.\d+)", re.I),
}
# Below these versions are considered notably dated (illustrative).
LIB_MIN = {"jquery": (3, 5, 0), "bootstrap": (4, 0, 0), "angular": (1, 8, 0)}


def _ver_tuple(v: str):
    return tuple(int(x) for x in v.split("."))


def run(url: str, result, timeout: int = 15) -> None:
    result.mark_check("Content & technology analysis")
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            verify=True, headers={"User-Agent": UA})
    except Exception:  # noqa: BLE001
        return
    html = resp.text or ""
    base_https = resp.url.startswith("https://")

    # --- Mixed content ---
    if base_https:
        mixed = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', html, re.I)
        mixed = [m for m in mixed if not m.startswith("http://www.w3.org")]
        if mixed:
            result.add(Finding(
                title="Mixed content: HTTP resources on an HTTPS page",
                severity="medium", cwe="CWE-311: Missing Encryption of Sensitive Data",
                category="A02: Cryptographic Failures",
                description="The HTTPS page references resources over plain HTTP.",
                impact="Mixed content can be intercepted or modified and weakens "
                       "the page's security guarantees.",
                evidence="e.g. " + "; ".join(mixed[:5]),
                recommendation="Serve all resources over HTTPS; add "
                               "'upgrade-insecure-requests' to the CSP.",
                attack_surface=["Man-in-the-middle", "Content injection"],
                affected=resp.url, check="content",
            ))

    # --- CMS / generator fingerprint ---
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    html, re.I)
    fingerprints = []
    if gen:
        fingerprints.append(gen.group(1))
    if "/wp-content/" in html or "/wp-includes/" in html:
        fingerprints.append("WordPress")
    if "Drupal.settings" in html or "/sites/default/files" in html:
        fingerprints.append("Drupal")
    if "Joomla" in html or "/media/jui/" in html:
        fingerprints.append("Joomla")
    if fingerprints:
        result.meta["fingerprints"] = fingerprints
        result.add(Finding(
            title="Software/CMS fingerprint disclosed in page",
            severity="info", cwe="CWE-200: Information Exposure",
            category="A05: Security Misconfiguration",
            description="The page reveals the underlying CMS/framework.",
            impact="Helps an attacker select version-specific exploits.",
            evidence="; ".join(fingerprints[:5]),
            recommendation="Remove generator meta tags and avoid default paths "
                           "where feasible.",
            attack_surface=["Targeted exploitation of known CVEs"],
            affected=resp.url, check="content",
        ))

    # --- Outdated JS libraries ---
    for name, pat in LIB_PATTERNS.items():
        m = pat.search(html)
        if m:
            try:
                if _ver_tuple(m.group(1)) < LIB_MIN[name]:
                    result.add(Finding(
                        title=f"Potentially outdated library: {name} {m.group(1)}",
                        severity="low",
                        cwe="CWE-1104: Use of Unmaintained Third Party Components",
                        category="A06: Vulnerable & Outdated Components",
                        description=f"The page loads {name} {m.group(1)}, which is "
                                    "older than a current baseline.",
                        impact="Outdated client libraries may contain known XSS or "
                               "prototype-pollution issues.",
                        evidence=f"Detected {name} version {m.group(1)}",
                        recommendation=f"Upgrade {name} to a supported release and "
                                       "track dependencies.",
                        attack_surface=["Exploitation of known client-side CVEs"],
                        affected=resp.url, check="content",
                    ))
            except ValueError:
                pass

    # --- Forms without apparent CSRF token ---
    forms = re.findall(r"<form\b.*?</form>", html, re.I | re.S)
    for form in forms:
        if re.search(r'method=["\']?post', form, re.I):
            if not re.search(r"csrf|authenticity_token|__requestverificationtoken|"
                             r"nonce", form, re.I):
                result.add(Finding(
                    title="POST form without visible anti-CSRF token",
                    severity="low", cwe="CWE-352: Cross-Site Request Forgery",
                    category="A01: Broken Access Control",
                    description="A POST form has no obvious anti-CSRF token field. "
                                "This is a heuristic and may be a false positive if "
                                "the token is injected dynamically.",
                    impact="If unprotected, an attacker could forge state-changing "
                           "requests on behalf of a logged-in user.",
                    evidence=form[:160].replace("\n", " "),
                    recommendation="Ensure all state-changing POST forms include a "
                                   "server-validated CSRF token.",
                    attack_surface=["Cross-Site Request Forgery (CSRF)"],
                    affected=resp.url, confidence="Low", check="content",
                )); break  # one representative finding is enough
