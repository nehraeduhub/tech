"""Optional integration with well-known open-source scanners.

If these tools happen to be installed on the host (e.g. a security workstation),
the portal shells out to them in their standard, non-aggressive modes and folds
a summary into the report. If they are absent, the portal silently relies on its
built-in pure-Python checks -- so it still "just runs" from a USB stick.

Supported (all open-source, widely used in professional VAPT):
  * nmap        - service/port discovery (-T3, top ports only)
  * nikto       - web server misconfiguration scanner
  * testssl.sh  - TLS configuration auditor

Only safe, standard invocations are used. Timing is conservative and no
exploit/brute-force flags are passed.
"""
from __future__ import annotations

import shutil
import subprocess
from urllib.parse import urlparse

from ..models import Finding

TOOL_TIMEOUT = 180  # seconds per external tool


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def available_tools() -> dict[str, bool]:
    return {t: _which(t) is not None for t in ("nmap", "nikto", "testssl.sh")}


def run(url: str, result) -> None:
    host = urlparse(url).hostname
    if not host:
        return

    tools = available_tools()
    result.meta["external_tools"] = tools
    if not any(tools.values()):
        result.log("No external scanners detected; using built-in checks only")
        return

    if tools.get("nmap"):
        _run_nmap(host, result)
    if tools.get("nikto"):
        _run_nikto(url, result)
    if tools.get("testssl.sh") and url.startswith("https://"):
        _run_testssl(host, result)


def _exec(cmd: list[str], result) -> str:
    result.log("Running: " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT, check=False,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        result.errors.append(f"External tool timed out: {cmd[0]}")
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"External tool failed ({cmd[0]}): {exc}")
    return ""


def _run_nmap(host: str, result) -> None:
    # Top 100 ports, service version, no aggressive scripts.
    out = _exec(["nmap", "-T3", "-F", "-sV", "--open", host], result)
    if not out:
        return
    open_ports = [ln.strip() for ln in out.splitlines()
                  if "/tcp" in ln and "open" in ln]
    if open_ports:
        result.meta["nmap_open_ports"] = open_ports
        result.add(Finding(
            title="Open network services discovered (nmap)",
            severity="info",
            category="A05: Security Misconfiguration",
            description="nmap identified listening services. Review that each is "
                        "intended to be internet-facing and is patched.",
            evidence="\n".join(open_ports[:20]),
            recommendation="Close or firewall any service not required for public "
                           "access; keep exposed services patched.",
            attack_surface=["Service-specific exploitation", "Attack surface growth"],
            references=["https://nmap.org/"],
            check="external:nmap",
        ))


def _run_nikto(url: str, result) -> None:
    out = _exec(["nikto", "-h", url, "-maxtime", "120s", "-Tuning", "123b"], result)
    if not out:
        return
    hits = [ln.strip() for ln in out.splitlines()
            if ln.strip().startswith("+") and "0 host(s)" not in ln]
    if hits:
        result.add(Finding(
            title="Web server issues reported by nikto",
            severity="medium",
            category="A05: Security Misconfiguration",
            description="nikto reported potential misconfigurations or dated "
                        "components. Validate each item manually.",
            evidence="\n".join(hits[:25]),
            recommendation="Address each reported item; many are header or outdated "
                           "software issues.",
            attack_surface=["Depends on specific finding"],
            references=["https://github.com/sullo/nikto"],
            check="external:nikto",
        ))


def _run_testssl(host: str, result) -> None:
    out = _exec(["testssl.sh", "--quiet", "--color", "0", host], result)
    if not out:
        return
    bad = [ln.strip() for ln in out.splitlines()
           if any(k in ln.upper() for k in ("VULNERABLE", "NOT OK", "WEAK"))]
    if bad:
        result.add(Finding(
            title="TLS configuration weaknesses (testssl.sh)",
            severity="medium",
            category="A02: Cryptographic Failures",
            description="testssl.sh flagged weak ciphers, protocols or known TLS "
                        "vulnerabilities.",
            evidence="\n".join(bad[:25]),
            recommendation="Harden the TLS configuration; disable weak ciphers and "
                           "protocols.",
            attack_surface=["Protocol/cipher attacks", "MITM"],
            references=["https://github.com/drwetter/testssl.sh"],
            check="external:testssl",
        ))
