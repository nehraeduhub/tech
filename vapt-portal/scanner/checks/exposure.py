"""Checks for inadvertently exposed files, admin panels and directory listing.

Performs only GET requests to well-known conventional paths and reports when
something sensitive appears readable. It never downloads bulk data, never
guesses credentials, and never writes to the target.
"""
from __future__ import annotations

import requests

from ..models import Finding

UA = "Tech Guardians-VAPT/2.0 (authorised security assessment)"

# Conventional paths that should normally NOT be publicly readable.
SENSITIVE_PATHS = {
    "/.git/config": ("Exposed .git repository", "high", "CWE-527",
                     ["Source code & secret disclosure"]),
    "/.env": ("Exposed .env configuration file", "critical", "CWE-538",
              ["Credential & secret disclosure"]),
    "/.svn/entries": ("Exposed .svn metadata", "high", "CWE-527",
                      ["Source code disclosure"]),
    "/backup.zip": ("Publicly accessible backup archive", "high", "CWE-530",
                    ["Full data/source disclosure"]),
    "/backup.sql": ("Publicly accessible database dump", "critical", "CWE-530",
                    ["Full database disclosure"]),
    "/phpinfo.php": ("Exposed phpinfo()", "medium", "CWE-200",
                     ["Environment & path disclosure"]),
    "/server-status": ("Apache server-status exposed", "medium", "CWE-200",
                       ["Internal activity disclosure"]),
    "/.DS_Store": ("Exposed .DS_Store directory index", "low", "CWE-527",
                   ["Directory structure disclosure"]),
    "/wp-config.php.bak": ("Exposed WordPress config backup", "critical", "CWE-530",
                           ["Database credential disclosure"]),
    "/config.php.bak": ("Exposed config backup", "high", "CWE-530",
                        ["Credential disclosure"]),
    "/.htpasswd": ("Exposed .htpasswd file", "high", "CWE-538",
                   ["Password hash disclosure"]),
    "/web.config": ("Exposed web.config", "medium", "CWE-200",
                    ["Configuration disclosure"]),
    "/.aws/credentials": ("Exposed AWS credentials file", "critical", "CWE-538",
                          ["Cloud account compromise"]),
}

ADMIN_PATHS = {
    "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/manager/html", "/.git/HEAD", "/actuator", "/actuator/health",
}

INFO_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")


def _get(url: str, timeout: int):
    return requests.get(url, timeout=timeout, allow_redirects=False, verify=True,
                        headers={"User-Agent": UA})


def run(base_url: str, result, timeout: int = 10) -> None:
    base = base_url.rstrip("/")
    result.mark_check("Sensitive file & path exposure")
    result.log("Checking for exposed sensitive files and admin interfaces")

    for path, (title, severity, cwe, attack) in SENSITIVE_PATHS.items():
        try:
            resp = _get(base + path, timeout)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            snippet = (resp.text[:120].replace("\n", " ") if resp.text else "")
            result.add(Finding(
                title=title, severity=severity, cwe=f"{cwe}: Sensitive File Exposure",
                category="A01: Broken Access Control",
                description=f"The path {path} responded with HTTP 200, suggesting a "
                            "sensitive resource is publicly readable.",
                impact="Disclosed source, backups or secrets can lead directly to "
                       "full compromise.",
                evidence=f"GET {base + path} -> 200 ({len(resp.content)} bytes) "
                         f"{snippet!r}",
                recommendation=f"Block public access to {path} or move it outside "
                               "the web root.",
                attack_surface=attack, affected=base + path, confidence="High",
                check="exposure",
            ))

    # Admin panels discoverable (informational unless clearly open).
    found_admin = []
    for path in ADMIN_PATHS:
        try:
            resp = _get(base + path, timeout)
            if resp.status_code in (200, 401, 403):
                found_admin.append(f"{path} ({resp.status_code})")
        except Exception:  # noqa: BLE001
            continue
    if found_admin:
        result.meta["admin_endpoints"] = found_admin
        result.add(Finding(
            title="Administrative interface(s) reachable",
            severity="low", cwe="CWE-284: Improper Access Control",
            category="A01: Broken Access Control",
            description="Administrative or management endpoints respond to requests "
                        "from the internet.",
            impact="Exposed admin panels invite brute-force and targeted attacks.",
            evidence="; ".join(found_admin[:10]),
            recommendation="Restrict admin interfaces by IP/VPN and enforce strong, "
                           "MFA-backed authentication.",
            attack_surface=["Brute force", "Credential stuffing"],
            affected=base, check="exposure",
        ))

    # Informational files.
    found_info = []
    for path in INFO_PATHS:
        try:
            if _get(base + path, timeout).status_code == 200:
                found_info.append(path)
        except Exception:  # noqa: BLE001
            continue
    if found_info:
        result.meta["info_files"] = found_info
        if "/.well-known/security.txt" not in found_info:
            result.add(Finding(
                title="No security.txt disclosure policy published",
                severity="info", category="A05: Security Misconfiguration",
                description="No /.well-known/security.txt was found. This file "
                            "advertises how to report vulnerabilities.",
                impact="Researchers have no clear channel to report issues.",
                evidence="security.txt not present.",
                recommendation="Publish /.well-known/security.txt per RFC 9116.",
                affected=base, check="exposure",
            ))

    # Directory listing on web root.
    try:
        resp = _get(base + "/", timeout)
        if resp.status_code == 200 and "index of /" in (resp.text or "").lower():
            result.add(Finding(
                title="Directory listing enabled",
                severity="medium", cwe="CWE-548: Information Exposure Through Listing",
                category="A05: Security Misconfiguration",
                description="The web server returns an auto-generated directory "
                            "index, revealing file structure.",
                impact="Attackers can enumerate files and discover unlinked content.",
                evidence="Response body contains 'Index of /'.",
                recommendation="Disable automatic directory indexing "
                               "('Options -Indexes' on Apache).",
                attack_surface=["Information disclosure", "File enumeration"],
                affected=base, check="exposure",
            ))
    except Exception:  # noqa: BLE001
        pass
