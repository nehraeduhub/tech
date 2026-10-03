"""HTTP security-header, cookie, redirect and method checks.

All requests are plain GET/HEAD/OPTIONS. Nothing here sends a payload or tries
to exploit anything -- it reads what the server volunteers and reports gaps.
"""
from __future__ import annotations

import requests

from ..models import Finding

UA = "RJHex-VAPT/2.0 (authorised security assessment)"

# Headers we expect a well-hardened site to send, with the risk when missing.
SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HSTS (Strict-Transport-Security) header",
        "severity": "medium", "cwe": "CWE-319: Cleartext Transmission",
        "category": "A05: Security Misconfiguration",
        "desc": "The response does not set Strict-Transport-Security, so browsers "
                "are not forced to use HTTPS on subsequent visits.",
        "impact": "An attacker on the network path can downgrade the connection to "
                  "HTTP and intercept or modify traffic.",
        "rec": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
               "preload' once HTTPS is confirmed everywhere.",
        "attack": ["SSL stripping / downgrade", "Man-in-the-middle"],
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": "medium", "cwe": "CWE-693: Protection Mechanism Failure",
        "category": "A05: Security Misconfiguration",
        "desc": "No Content-Security-Policy is defined. CSP is the primary defence "
                "that limits where scripts and resources may load from.",
        "impact": "Injected or malicious scripts are not constrained, increasing "
                  "the impact of any XSS flaw.",
        "rec": "Define a restrictive CSP (e.g. default-src 'self') and tighten it "
               "iteratively.",
        "attack": ["Cross-Site Scripting (XSS)", "Data injection", "Clickjacking"],
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options / frame-ancestors",
        "severity": "medium", "cwe": "CWE-1021: Improper Restriction of Rendered UI",
        "category": "A05: Security Misconfiguration",
        "desc": "The page can be embedded in a frame on another origin, enabling "
                "clickjacking.",
        "impact": "An attacker can overlay the site in a hidden frame to trick "
                  "users into unintended actions.",
        "rec": "Set 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP "
               "frame-ancestors directive.",
        "attack": ["Clickjacking / UI redress"],
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": "low", "cwe": "CWE-16: Configuration",
        "category": "A05: Security Misconfiguration",
        "desc": "Without 'nosniff', browsers may MIME-sniff responses and execute "
                "content in an unintended way.",
        "impact": "Content may be interpreted as a different type, enabling some "
                  "XSS and drive-by scenarios.",
        "rec": "Set 'X-Content-Type-Options: nosniff'.",
        "attack": ["MIME-sniffing based XSS"],
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": "low", "cwe": "CWE-200: Information Exposure",
        "category": "A05: Security Misconfiguration",
        "desc": "No Referrer-Policy set; full URLs (possibly with tokens) may leak "
                "to third parties via the Referer header.",
        "impact": "Sensitive URL parameters can leak to external sites.",
        "rec": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
        "attack": ["Sensitive information disclosure"],
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "severity": "info", "cwe": "CWE-16: Configuration",
        "category": "A05: Security Misconfiguration",
        "desc": "No Permissions-Policy present to restrict powerful browser "
                "features (camera, geolocation, etc.).",
        "impact": "Injected content could access browser features the site does "
                  "not need.",
        "rec": "Add a Permissions-Policy that disables unused features.",
        "attack": ["Abuse of browser features via injected content"],
    },
    "cross-origin-opener-policy": {
        "title": "Missing Cross-Origin-Opener-Policy header",
        "severity": "info", "cwe": "CWE-16: Configuration",
        "category": "A05: Security Misconfiguration",
        "desc": "COOP is not set; the page shares a browsing context group with "
                "cross-origin openers.",
        "impact": "Weakens isolation against cross-origin attacks (e.g. XS-Leaks).",
        "rec": "Set 'Cross-Origin-Opener-Policy: same-origin'.",
        "attack": ["Cross-origin information leaks"],
    },
}


def _request(url: str, method: str, timeout: int, verify: bool = True):
    return requests.request(
        method, url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": UA}, verify=verify,
    )


def run(url: str, result, timeout: int = 15) -> None:
    result.mark_check("HTTP security headers")
    result.log("Checking HTTP security headers, cookies and methods")
    try:
        resp = _request(url, "GET", timeout)
    except requests.exceptions.SSLError:
        try:
            resp = _request(url, "GET", timeout, verify=False)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"HTTP header check failed: {exc}")
            return
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"HTTP header check failed: {exc}")
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    result.meta["final_url"] = resp.url
    result.meta["status_code"] = resp.status_code
    result.meta["response_headers"] = dict(resp.headers)

    # --- Missing security headers ---
    for key, spec in SECURITY_HEADERS.items():
        if key not in headers:
            result.add(Finding(
                title=spec["title"], severity=spec["severity"],
                category=spec["category"], cwe=spec["cwe"],
                description=spec["desc"], impact=spec["impact"],
                evidence=f"Response from {resp.url} did not include the "
                         f"'{key}' header.",
                recommendation=spec["rec"], attack_surface=spec["attack"],
                affected=resp.url, confidence="High",
                references=["https://owasp.org/www-project-secure-headers/"],
                check="http_security",
            ))

    # --- HSTS present but no preload / short max-age ---
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age" in hsts:
        try:
            maxage = int(hsts.split("max-age=")[1].split(";")[0])
            if maxage < 15552000:
                result.add(Finding(
                    title="HSTS max-age is below recommended minimum",
                    severity="low", cwe="CWE-319: Cleartext Transmission",
                    category="A05: Security Misconfiguration",
                    description="HSTS is enabled but max-age is short, shrinking the "
                                "window of HTTPS enforcement.",
                    impact="Users returning after the window elapses are briefly "
                           "exposed to downgrade attacks.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="Use max-age of at least 15552000 (180 days); "
                                   "31536000 (1 year) is recommended.",
                    attack_surface=["SSL stripping"], affected=resp.url,
                    check="http_security",
                ))
        except (ValueError, IndexError):
            pass

    # --- Technology disclosure ---
    for disclose in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if headers.get(disclose, "").strip():
            result.add(Finding(
                title=f"Technology disclosure via '{disclose}' header",
                severity="info", cwe="CWE-200: Information Exposure",
                category="A05: Security Misconfiguration",
                description="The server advertises software/version details that "
                            "help an attacker target known vulnerabilities.",
                impact="Narrows an attacker's research to known CVEs for the "
                       "disclosed component.",
                evidence=f"{disclose}: {headers[disclose]}",
                recommendation="Suppress or genericise version banners.",
                attack_surface=["Targeted exploitation of known CVEs"],
                affected=resp.url, check="http_security",
            ))

    # --- Caching of potentially sensitive responses ---
    cache = headers.get("cache-control", "").lower()
    if cache and not any(d in cache for d in ("no-store", "no-cache", "private")):
        result.add(Finding(
            title="Response may be cached by shared caches",
            severity="info", cwe="CWE-525: Information Exposure Through Caching",
            category="A05: Security Misconfiguration",
            description="Cache-Control does not prevent caching; sensitive pages "
                        "could be stored by proxies or the browser.",
            impact="Sensitive content may persist in shared or browser caches.",
            evidence=f"Cache-Control: {headers.get('cache-control')}",
            recommendation="Set 'Cache-Control: no-store' on authenticated or "
                           "sensitive responses.",
            affected=resp.url, check="http_security",
        ))

    _check_cookies(resp, result)
    _check_redirect(url, resp, result)
    _check_methods(url, result, timeout)


def _check_cookies(resp, result) -> None:
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        rest = {k.lower() for k in getattr(cookie, "_rest", {}).keys()}
        if "httponly" not in rest:
            issues.append("missing HttpOnly flag")
        if "samesite" not in rest:
            issues.append("missing SameSite attribute")
        if issues:
            result.add(Finding(
                title=f"Insecure cookie attributes: {cookie.name}",
                severity="medium", cwe="CWE-614: Sensitive Cookie Without Secure",
                category="A05: Security Misconfiguration",
                description="A cookie is set without recommended protective "
                            "flags: " + ", ".join(issues) + ".",
                impact="Session cookies may be exposed to theft over HTTP or via "
                       "client-side script.",
                evidence=f"Set-Cookie: {cookie.name} ({', '.join(issues)})",
                recommendation="Set Secure, HttpOnly and SameSite on sensitive "
                               "cookies.",
                attack_surface=["Session hijacking", "XSS cookie theft", "CSRF"],
                affected=resp.url, confidence="High", check="http_security",
            ))


def _check_redirect(url, resp, result) -> None:
    if url.startswith("http://") and not resp.url.startswith("https://"):
        result.add(Finding(
            title="Site does not redirect HTTP to HTTPS",
            severity="high", cwe="CWE-319: Cleartext Transmission",
            category="A02: Cryptographic Failures",
            description="Plain HTTP requests are served without redirecting to "
                        "HTTPS, so traffic can be intercepted.",
            impact="All traffic, including credentials, can be read or modified "
                   "by a network attacker.",
            evidence=f"GET {url} ended at {resp.url}",
            recommendation="Force a 301 redirect from HTTP to HTTPS site-wide.",
            attack_surface=["Man-in-the-middle", "Credential interception"],
            affected=url, confidence="High", check="http_security",
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
                    severity="medium", cwe="CWE-650: Trusting HTTP Methods",
                    category="A05: Security Misconfiguration",
                    description="The server advertises HTTP methods that can be "
                                "misused if not strictly controlled.",
                    impact="Methods such as PUT/DELETE/TRACE may allow unauthorised "
                           "writes or cross-site tracing.",
                    evidence=f"Allow: {allow}",
                    recommendation="Disable methods the application does not need "
                                   "(especially TRACE, PUT, DELETE).",
                    attack_surface=["Cross-Site Tracing", "Unauthorised writes"],
                    affected=url, check="http_security",
                ))
    except Exception:  # noqa: BLE001
        pass
