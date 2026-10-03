"""Scan orchestration.

The engine normalises the target, runs each non-intrusive check, and returns a
ScanResult. It is deliberately conservative: it assesses configuration and
exposure rather than attempting exploitation.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import ScanResult
from .checks import http_security, tls, exposure, dns_info, external_tools

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
    deep_dns: bool = True,
) -> ScanResult:
    url = normalize_target(raw_target)
    result = ScanResult(target=raw_target, normalized_url=url)
    result.started_at = datetime.now(timezone.utc).isoformat()
    result.log(f"Assessment started against {url}")

    # Pure-Python, always-available checks.
    for name, fn in (
        ("HTTP security", lambda: http_security.run(url, result)),
        ("TLS", lambda: tls.run(url, result)),
        ("Exposure", lambda: exposure.run(url, result)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"{name} check error: {exc}")

    if deep_dns:
        try:
            dns_info.run(url, result)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"DNS check error: {exc}")

    # Optional external scanners (only if installed on the host).
    if use_external_tools:
        try:
            external_tools.run(url, result)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"External tool error: {exc}")

    if not result.findings:
        result.log("No issues detected by the automated checks")

    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.log(
        f"Assessment complete: {len(result.findings)} finding(s), "
        f"risk rating {result.risk_rating()}"
    )
    return result
