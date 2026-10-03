"""Scan orchestration.

The engine normalises the target, runs each check, and returns a ScanResult.
Built-in checks are non-intrusive. External Kali/open-source tools are run only
if installed, and the active (intrusive) ones only when the operator enables
active scanning for an authorised engagement.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import config
from .models import ScanResult
from .checks import (
    http_security, tls, exposure, email_dns, cors, content, ports, waf,
    external_tools,
)

_HOST_RE = re.compile(r"^[a-zA-Z0-9.\-:]+$")


def normalize_target(raw: str) -> str:
    """Turn user input into a well-formed URL. Defaults to https://."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty target")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname or not _HOST_RE.match(parsed.hostname):
        raise ValueError("Target does not look like a valid hostname or URL")
    return raw


def run_scan(
    raw_target: str,
    *,
    use_external_tools: bool = True,
    enable_active_tools: bool = True,
    port_scan: bool = True,
    deep_dns: bool = True,
) -> ScanResult:
    url = normalize_target(raw_target)
    timeout = config.DEFAULT_HTTP_TIMEOUT
    result = ScanResult(target=raw_target, normalized_url=url)
    result.started_at = datetime.now(timezone.utc).isoformat()
    result.log(f"Assessment started against {url}")

    # Pure-Python, always-available checks.
    builtins = [
        ("HTTP security", lambda: http_security.run(url, result, timeout)),
        ("TLS", lambda: tls.run(url, result, timeout)),
        ("Security headers CORS", lambda: cors.run(url, result, timeout)),
        ("Content analysis", lambda: content.run(url, result, timeout)),
        ("Exposure", lambda: exposure.run(url, result, timeout)),
        ("WAF detection", lambda: waf.run(url, result, timeout)),
    ]
    for name, fn in builtins:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{name} check error: {exc}")

    if deep_dns:
        try:
            email_dns.run(url, result)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"DNS check error: {exc}")

    if port_scan:
        try:
            ports.run(url, result)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Port scan error: {exc}")

    # External scanners (only those installed; active ones gated).
    if use_external_tools:
        try:
            external_tools.run(url, result, enable_active=enable_active_tools)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"External tool error: {exc}")

    if not result.findings:
        result.log("No issues detected by the automated checks")

    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.log(
        f"Assessment complete: {len(result.findings)} finding(s), "
        f"risk rating {result.risk_rating()}, grade {result.security_grade()}"
    )
    return result
