"""Checks for inadvertently exposed files and directory listing.

This performs only GET requests to well-known conventional paths and reports
when something sensitive appears to be readable. It never downloads bulk data,
never guesses credentials, and never writes anything to the target.
"""
from __future__ import annotations

import requests

from ..models import Finding

# Conventional paths that should normally NOT be publicly readable.
SENSITIVE_PATHS = {
    "/.git/config": ("Exposed .git repository", "high",
                     ["Source code & secret disclosure"]),
    "/.env": ("Exposed .env configuration file", "critical",
              ["Credential & secret disclosure"]),
    "/.svn/entries": ("Exposed .svn metadata", "high",
                      ["Source code disclosure"]),
    "/backup.zip": ("Publicly accessible backup archive", "high",
                    ["Full data/source disclosure"]),
    "/phpinfo.php": ("Exposed phpinfo()", "medium",
                     ["Environment & path disclosure"]),
    "/server-status": ("Apache server-status exposed", "medium",
                       ["Internal activity disclosure"]),
    "/.DS_Store": ("Exposed .DS_Store directory index", "low",
                   ["Directory structure disclosure"]),
    "/wp-config.php.bak": ("Exposed WordPress config backup", "critical",
                           ["Database credential disclosure"]),
}

INFO_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")


def _get(url: str, timeout: int):
    return requests.get(
        url, timeout=timeout, allow_redirects=False, verify=True,
        headers={"User-Agent": "TechGuardians-VAPT/1.0 (authorised assessment)"},
    )


def run(base_url: str, result, timeout: int = 10) -> None:
    base = base_url.rstrip("/")
    result.log("Checking for exposed sensitive files")

    for path, (title, severity, attack) in SENSITIVE_PATHS.items():
        try:
            resp = _get(base + path, timeout)
        except Exception:  # noqa: BLE001
            continue
        # Only flag a genuine 200 with a non-trivial body.
        if resp.status_code == 200 and len(resp.content) > 0:
            snippet = resp.text[:120].replace("\n", " ") if resp.text else ""
            result.add(Finding(
                title=title,
                severity=severity,
                category="A01: Broken Access Control",
                description=f"The path {path} responded with HTTP 200, suggesting "
                            "a sensitive resource is publicly readable.",
                evidence=f"GET {base + path} -> 200 ({len(resp.content)} bytes) "
                         f"{snippet!r}",
                recommendation=f"Block public access to {path} at the web server "
                               "or move it outside the web root.",
                attack_surface=attack,
                check="exposure",
            ))

    # Informational: note presence of robots/sitemap (useful context, not a flaw).
    found_info = []
    for path in INFO_PATHS:
        try:
            resp = _get(base + path, timeout)
            if resp.status_code == 200:
                found_info.append(path)
        except Exception:  # noqa: BLE001
            continue
    if found_info:
        result.meta["info_files"] = found_info

    # Directory listing on the web root.
    try:
        resp = _get(base + "/", timeout)
        body = (resp.text or "").lower()
        if resp.status_code == 200 and "index of /" in body:
            result.add(Finding(
                title="Directory listing enabled",
                severity="medium",
                category="A05: Security Misconfiguration",
                description="The web server returns an auto-generated directory "
                            "index, revealing file structure.",
                evidence="Response body contains 'Index of /'.",
                recommendation="Disable automatic directory indexing (e.g. "
                               "'Options -Indexes' on Apache).",
                attack_surface=["Information disclosure", "File enumeration"],
                check="exposure",
            ))
    except Exception:  # noqa: BLE001
        pass
