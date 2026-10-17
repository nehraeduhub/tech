"""Penetration-testing tool orchestration (exploitation verification).

Drives well-known open-source / Kali exploitation tools in SAFE, standard,
confirmation-oriented modes to verify (not weaponise) vulnerabilities, and folds
their results into the report. Each tool runs only if it is installed and only
when PT mode is enabled for an authorised engagement.

Supported (install whichever you have — see TOOLS.md):
  sqlmap   - SQL injection confirmation (low level/risk, batch)
  dalfox   - XSS confirmation
  commix   - command-injection confirmation (batch)
  xsstrike - XSS fuzzing
  nmap     - service vulnerability scripts (--script vuln)
  nuclei   - template-based CVE/exposure checks (also used in VA layer)
"""
from __future__ import annotations

import shutil
import subprocess
from urllib.parse import urlparse

from ..models import Finding

TOOL_TIMEOUT = 300

PT_TOOLS = {
    "sqlmap": "SQL injection", "dalfox": "XSS", "commix": "command injection",
    "xsstrike": "XSS", "nmap": "service vuln scripts", "nuclei": "CVE/exposure",
}


def available_pt_tools() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in PT_TOOLS}


def _exec(cmd, result, timeout=TOOL_TIMEOUT):
    result.log("PT: " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           check=False)
        return (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired:
        result.errors.append(f"PT tool timed out: {cmd[0]}")
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"PT tool failed ({cmd[0]}): {exc}")
    return ""


def run(base_url: str, surface: dict, result) -> None:
    host = urlparse(base_url).hostname
    tools = available_pt_tools()
    result.meta["pt_tools"] = tools
    present = [t for t, ok in tools.items() if ok]
    if not present:
        result.log("No PT tools installed; using built-in injection probes only")
        return
    result.mark_check(f"PT exploitation tools ({', '.join(present)})")

    param_urls = [gp["url"] for gp in surface.get("get_params", [])][:3]
    if not param_urls:
        param_urls = [base_url]

    if tools.get("sqlmap"):
        for u in param_urls:
            _sqlmap(u, result)
    if tools.get("dalfox"):
        for u in param_urls:
            _dalfox(u, result)
    if tools.get("xsstrike") and not tools.get("dalfox"):
        for u in param_urls[:1]:
            _xsstrike(u, result)
    if tools.get("commix"):
        _commix(param_urls[0], result)
    if tools.get("nmap") and host:
        _nmap_vuln(host, result)


def _finding(result, title, sev, cwe, cat, desc, impact, evidence, rec, tool,
             affected):
    result.add(Finding(
        title=title, severity=sev, cwe=cwe, category=cat, description=desc,
        impact=impact, evidence=evidence, recommendation=rec, affected=affected,
        confidence="Confirmed", check=f"pt:{tool}",
        attack_surface=["Exploitation confirmed by tool"]))


def _sqlmap(url, result):
    out = _exec(["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
                 "--disable-coloring", "--flush-session", "--smart"], result)
    low = out.lower()
    if "is vulnerable" in low or "sqlmap identified the following injection" in low:
        hits = [l.strip() for l in out.splitlines()
                if "Parameter:" in l or "Type:" in l or "Title:" in l][:12]
        _finding(result, "SQL Injection confirmed by sqlmap", "critical",
                 "CWE-89: SQL Injection", "A03: Injection",
                 "sqlmap confirmed an injectable parameter.",
                 "Full database compromise is possible.",
                 "\n".join(hits) or "sqlmap reported the target is injectable.",
                 "Use parameterised queries; review all DB access paths.",
                 "sqlmap", url)


def _dalfox(url, result):
    out = _exec(["dalfox", "url", url, "--silence", "--no-color"], result)
    hits = [l.strip() for l in out.splitlines() if "[POC]" in l or "[VULN]" in l][:12]
    if hits:
        _finding(result, "Cross-Site Scripting confirmed by dalfox", "high",
                 "CWE-79: Cross-site Scripting", "A03: Injection",
                 "dalfox produced a working XSS proof-of-concept.",
                 "Arbitrary script execution in victims' browsers.",
                 "\n".join(hits), "Context-encode output; enforce a strict CSP.",
                 "dalfox", url)


def _xsstrike(url, result):
    out = _exec(["xsstrike", "-u", url, "--skip"], result, timeout=180)
    if "reflection" in out.lower() and "vulnerable" in out.lower():
        _finding(result, "Cross-Site Scripting reported by XSStrike", "high",
                 "CWE-79: Cross-site Scripting", "A03: Injection",
                 "XSStrike reported a reflected XSS vector.",
                 "Arbitrary script execution in victims' browsers.",
                 "See XSStrike output in the assessment log.",
                 "Context-encode output; enforce a strict CSP.", "xsstrike", url)


def _commix(url, result):
    out = _exec(["commix", "--url", url, "--batch", "--level=1"], result,
                timeout=180)
    if "is vulnerable" in out.lower() or "command injection" in out.lower():
        _finding(result, "OS Command Injection confirmed by commix", "critical",
                 "CWE-78: OS Command Injection", "A03: Injection",
                 "commix confirmed command injection on the target.",
                 "Arbitrary command execution — full server compromise.",
                 "commix reported the parameter is injectable.",
                 "Never pass user input to a shell; use safe APIs.", "commix", url)


def _nmap_vuln(host, result):
    out = _exec(["nmap", "-sV", "--script", "vuln", "-T4", "--open", host], result)
    vulns = [l.strip() for l in out.splitlines()
             if "VULNERABLE" in l or "CVE-" in l][:20]
    if vulns:
        _finding(result, "Service vulnerabilities reported by nmap NSE", "high",
                 "CWE-1395: Vulnerable Component", "A06: Vulnerable & Outdated "
                 "Components",
                 "nmap vulnerability scripts flagged known issues in exposed "
                 "services.",
                 "Known CVEs may allow service compromise.",
                 "\n".join(vulns), "Patch/upgrade affected services; restrict "
                 "exposure.", "nmap-vuln", host)
