"""HTTP security-header, cookie, redirect and method checks.

All requests are plain GET/HEAD/OPTIONS. Nothing here sends a payload or tries
to exploit anything -- it reads what the server volunteers and reports gaps.
"""
from __future__ import annotations

import requests

from ..models import Finding

# Headers we expect a well-hardened site to send, with the risk when missing.
SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HSTS (Strict-Transport-Security) header",
        "severity": "medium",
        "category": "A05: Security Misconfiguration",
        "desc": "The response does not set Strict-Transport-Security, so browsers "
                "are not forced to use HTTPS on subsequent visits.",
        "rec": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
               "once HTTPS is confirmed working everywhere.",
        "attack": ["SSL stripping / downgrade", "Man-in-the-middle"],
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": "medium",
        "category": "A05: Security Misconfiguration",
        "desc": "No Content-Security-Policy is defined. CSP is the primary defence "
                "that limits where scripts and resources may load from.",
        "rec": "Define a restrictive CSP (e.g. default-src 'self') and tighten it "
               "iteratively.",
        "attack": ["Cross-Site Scripting (XSS)", "Data injection", "Clickjacking"],
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options / frame-ancestors",
        "severity": "medium",
        "category": "A05: Security Misconfiguration",
        "desc": "The page can be embedded in a frame on another origin, enabling "
                "clickjacking.",
        "rec": "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP "
               "frame-ancestors directive.",
        "attack": ["Clickjacking / UI redress"],
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": "low",
        "category": "A05: Security Misconfiguration",
        "desc": "Without 'nosniff', browsers may MIME-sniff responses and execute "
                "content in an unintended way.",
        "rec": "Set 'X-Content-Type-Options: nosniff'.",
        "attack": ["MIME-sniffing based XSS"],
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": "low",
        "category": "A05: Security Misconfiguration",
        "desc": "No Referrer-Policy set; full URLs (possibly with tokens) may leak "
                "to third parties via the Referer header.",
        "rec": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        "attack": ["Sensitive information disclosure"],
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "severity": "info",
        "category": "A05: Security Misconfiguration",
        "desc": "No Permissions-Policy present to restrict powerful browser "
                "features (camera, geolocation, etc.).",
        "rec": "Add a Permissions-Policy that disables features the site does not use.",
        "attack": ["Abuse of browser features via injected content"],
    },
}


def _request(url: str, method: str, timeout: int):
    return requests.request(
        method,
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "TechGuardians-VAPT/1.0 (authorised assessment)"},
        verify=True,
    )


def run(url: str, result, timeout: int = 15) -> None:
    result.log("Checking HTTP security headers")
    try:
        resp = _request(url, "GET", timeout)
    except requests.exceptions.SSLError:
        # Retry without strict verification only to READ headers; flagged elsewhere.
        try:
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True, verify=False,
                headers={"User-Agent": "TechGuardians-VAPT/1.0"},
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"HTTP header check failed: {exc}")
            return
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"HTTP header check failed: {exc}")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    result.meta["final_url"] = resp.url
    result.meta["status_code"] = resp.status_code

    # --- Missing security headers ---
    for key, spec in SECURITY_HEADERS.items():
        if key not in headers:
            result.add(Finding(
                title=spec["title"],
                severity=spec["severity"],
                category=spec["category"],
                description=spec["desc"],
                evidence=f"Response from {resp.url} did not include the "
                         f"'{key}' header.",
                recommendation=spec["rec"],
                attack_surface=spec["attack"],
                references=["https://owasp.org/www-project-secure-headers/"],
                check="http_security",
            ))

    # --- Server / technology disclosure ---
    for disclose in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if disclose in headers and headers[disclose].strip():
            result.add(Finding(
                title=f"Technology disclosure via '{disclose}' header",
                severity="info",
                category="A05: Security Misconfiguration",
                description="The server advertises software/version details that "
                            "help an attacker target known vulnerabilities.",
                evidence=f"{disclose}: {headers[disclose]}",
                recommendation="Suppress or genericise version banners.",
                attack_surface=["Targeted exploitation of known CVEs"],
                check="http_security",
            ))

    # --- Cookie flags ---
    _check_cookies(resp, result)

    # --- HTTPS redirect ---
    if url.startswith("http://") and not resp.url.startswith("https://"):
        result.add(Finding(
            title="Site does not redirect HTTP to HTTPS",
            severity="high",
            category="A02: Cryptographic Failures",
            description="Plain HTTP requests are served without redirecting to "
                        "HTTPS, so traffic can be intercepted.",
            evidence=f"GET {url} ended at {resp.url}",
            recommendation="Force a 301 redirect from HTTP to HTTPS site-wide.",
            attack_surface=["Man-in-the-middle", "Credential interception"],
            check="http_security",
        ))

    # --- Allowed methods (OPTIONS) ---
    _check_methods(url, result, timeout)


def _check_cookies(resp, result) -> None:
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        has_httponly = "httponly" in {k.lower() for k in cookie._rest.keys()}  # type: ignore[attr-defined]
        if not has_httponly:
            issues.append("missing HttpOnly flag")
        if issues:
            result.add(Finding(
                title=f"Insecure cookie attributes: {cookie.name}",
                severity="medium",
                category="A05: Security Misconfiguration",
                description="A session/application cookie is set without "
                            "recommended protective flags: " + ", ".join(issues) + ".",
                evidence=f"Set-Cookie: {cookie.name} ({', '.join(issues)})",
                recommendation="Set Secure, HttpOnly and SameSite on sensitive "
                               "cookies.",
                attack_surface=["Session hijacking", "XSS cookie theft"],
                check="http_security",
            ))


def _check_methods(url: str, result, timeout: int) -> None:
    try:
        resp = _request(url, "OPTIONS", timeout)
        allow = resp.headers.get("Allow") or resp.headers.get("allow")
        if allow:
            result.meta["allowed_methods"] = allow
            risky = {m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH")
                     if m in allow.upper()}
            if risky:
                result.add(Finding(
                    title="Potentially dangerous HTTP methods enabled",
                    severity="medium",
                    category="A05: Security Misconfiguration",
                    description="The server advertises HTTP methods that can be "
                                "misused if not strictly controlled.",
                    evidence=f"Allow: {allow}",
                    recommendation="Disable methods the application does not need "
                                   "(especially TRACE, PUT, DELETE).",
                    attack_surface=["Cross-Site Tracing", "Unauthorised writes"],
                    check="http_security",
                ))
    except Exception:  # noqa: BLE001
        pass
