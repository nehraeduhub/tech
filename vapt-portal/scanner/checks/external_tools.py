"""Integration with a wide set of open-source / Kali Linux security tools.

The portal auto-detects which tools are installed and runs each in a standard,
bounded mode. Nothing here is run unless the binary is present AND (for the
active/intrusive tools) the operator enabled active scanning in the portal.

Tools are grouped as:
  * PASSIVE  - recon / fingerprint / read-only (safe by default)
  * ACTIVE   - send many requests (dir brute force, template scans) -- only
               run when the operator ticks "active tools" (authorised testing).

Supported (install whichever you have; the portal uses what it finds):
  Recon/DNS : nmap, dnsrecon, dnsenum, fierce, whatweb, wafw00f, sublist3r,
              subfinder, amass, theHarvester, httpx
  TLS       : testssl.sh, sslscan, sslyze
  Web scan  : nikto, nuclei, wpscan, wapiti, gobuster, ffuf, dirb, feroxbuster
"""
from __future__ import annotations

import shutil
import subprocess
from urllib.parse import urlparse

from ..models import Finding

TOOL_TIMEOUT = 300  # seconds per external tool (bounded)


def _which(tool: str) -> str | None:
    return shutil.which(tool)


# Every tool the portal knows how to drive, with how intrusive it is.
KNOWN_TOOLS = {
    # passive / recon
    "nmap": "passive", "dnsrecon": "passive", "dnsenum": "passive",
    "fierce": "passive", "whatweb": "passive", "wafw00f": "passive",
    "sublist3r": "passive", "subfinder": "passive", "amass": "passive",
    "theHarvester": "passive", "httpx": "passive",
    "testssl.sh": "passive", "sslscan": "passive", "sslyze": "passive",
    "nikto": "passive",
    # active
    "nuclei": "active", "wpscan": "active", "wapiti": "active",
    "gobuster": "active", "ffuf": "active", "dirb": "active",
    "feroxbuster": "active",
}


def available_tools() -> dict[str, bool]:
    return {t: _which(t) is not None for t in KNOWN_TOOLS}


def _exec(cmd: list[str], result) -> str:
    result.log("Running: " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=TOOL_TIMEOUT, check=False)
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        result.errors.append(f"External tool timed out: {cmd[0]}")
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"External tool failed ({cmd[0]}): {exc}")
    return ""


def run(url: str, result, enable_active: bool = True) -> None:
    host = urlparse(url).hostname
    if not host:
        return
    tools = available_tools()
    result.meta["external_tools"] = tools
    present = [t for t, ok in tools.items() if ok]
    if not present:
        result.log("No external scanners detected; using built-in checks only")
        return
    result.mark_check(f"External tools ({', '.join(present)})")

    # ---- passive ----
    if tools.get("nmap"):
        _run_nmap(host, result)
    if tools.get("whatweb"):
        _run_simple(["whatweb", "--no-errors", url], result, "whatweb",
                    "Technology fingerprint (whatweb)", "info",
                    "A05: Security Misconfiguration")
    if tools.get("wafw00f"):
        _run_simple(["wafw00f", url], result, "wafw00f",
                    "WAF detection (wafw00f)", "info", "Defensive Control (positive)")
    if tools.get("dnsrecon"):
        _run_simple(["dnsrecon", "-d", host], result, "dnsrecon",
                    "DNS enumeration (dnsrecon)", "info",
                    "A05: Security Misconfiguration")
    if tools.get("sslscan"):
        _run_tls(["sslscan", "--no-colour", host], result, "sslscan")
    elif tools.get("testssl.sh") and url.startswith("https://"):
        _run_tls(["testssl.sh", "--quiet", "--color", "0", host], result, "testssl")
    if tools.get("nikto"):
        _run_nikto(url, result)
    for sub in ("subfinder", "sublist3r", "amass"):
        if tools.get(sub):
            _run_subdomains(sub, host, result)
            break

    # ---- active (only with consent) ----
    if not enable_active:
        result.log("Active external tools skipped (active scanning disabled)")
        return
    if tools.get("nuclei"):
        _run_nuclei(url, result)
    if tools.get("wpscan") and _looks_wordpress(result):
        _run_wpscan(url, result)
    if tools.get("wapiti"):
        _run_simple(["wapiti", "-u", url, "--flush-session", "-m",
                     "xss,sql,exec,file", "--max-scan-time", "120"],
                    result, "wapiti", "Active web scan (wapiti)", "medium",
                    "A03: Injection")
    for dirtool, cmd in (
        ("feroxbuster", ["feroxbuster", "-u", url, "-q", "--time-limit", "90s"]),
        ("gobuster", ["gobuster", "dir", "-u", url, "-w",
                      "/usr/share/wordlists/dirb/common.txt", "-q", "-t", "20"]),
        ("dirb", ["dirb", url, "-S", "-r"]),
    ):
        if tools.get(dirtool):
            _run_dirscan(cmd, result, dirtool)
            break


# --------------------------------------------------------------------------- #
def _run_nmap(host, result):
    out = _exec(["nmap", "-T4", "-F", "-sV", "--open", host], result)
    if not out:
        return
    ports = [ln.strip() for ln in out.splitlines() if "/tcp" in ln and "open" in ln]
    if ports:
        result.meta["nmap_open_ports"] = ports
        result.add(Finding(
            title="Open services discovered (nmap)", severity="info",
            category="A05: Security Misconfiguration",
            description="nmap identified listening services with version info.",
            impact="Each exposed service increases attack surface.",
            evidence="\n".join(ports[:25]),
            recommendation="Firewall unneeded services; keep the rest patched.",
            attack_surface=["Service-specific exploitation"],
            references=["https://nmap.org/"], affected=host, check="external:nmap",
        ))


def _run_nikto(url, result):
    out = _exec(["nikto", "-h", url, "-maxtime", "150s", "-Tuning", "123b"], result)
    hits = [ln.strip() for ln in out.splitlines()
            if ln.strip().startswith("+") and "0 host(s)" not in ln]
    if hits:
        result.add(Finding(
            title="Web server issues reported by nikto", severity="medium",
            category="A05: Security Misconfiguration", cwe="CWE-16: Configuration",
            description="nikto reported potential misconfigurations or dated "
                        "components. Validate each item manually.",
            impact="Varies per item; may include dated software or risky files.",
            evidence="\n".join(hits[:30]),
            recommendation="Remediate each reported item.",
            references=["https://github.com/sullo/nikto"], affected=url,
            check="external:nikto",
        ))


def _run_tls(cmd, result, tool):
    out = _exec(cmd, result)
    bad = [ln.strip() for ln in out.splitlines()
           if any(k in ln.upper() for k in
                  ("VULNERABLE", "NOT OK", "WEAK", "INSECURE", "SSLV", "TLSV1.0",
                   "TLSV1.1", "RC4", "EXPIRED"))]
    if bad:
        result.add(Finding(
            title=f"TLS configuration weaknesses ({tool})", severity="medium",
            category="A02: Cryptographic Failures",
            cwe="CWE-326: Inadequate Encryption Strength",
            description="The TLS auditor flagged weak protocols/ciphers or known "
                        "TLS vulnerabilities.",
            impact="Weak TLS can permit decryption or downgrade of traffic.",
            evidence="\n".join(bad[:30]),
            recommendation="Disable weak protocols/ciphers; require TLS 1.2+ "
                           "(prefer 1.3).",
            attack_surface=["Protocol/cipher attacks", "MITM"], affected=tool,
            check=f"external:{tool}",
        ))


def _run_subdomains(tool, host, result):
    root = ".".join(host.split(".")[-2:])
    cmds = {
        "subfinder": ["subfinder", "-silent", "-d", root],
        "sublist3r": ["sublist3r", "-d", root, "-n"],
        "amass": ["amass", "enum", "-passive", "-d", root, "-timeout", "3"],
    }
    out = _exec(cmds[tool], result)
    subs = sorted({ln.strip() for ln in out.splitlines()
                   if ln.strip().endswith(root) and " " not in ln.strip()})
    if subs:
        result.meta["subdomains"] = subs[:100]
        result.add(Finding(
            title=f"Subdomains enumerated ({tool})", severity="info",
            category="A05: Security Misconfiguration", cwe="CWE-200",
            description="Passive subdomain discovery expanded the known footprint.",
            impact="Each subdomain may host additional, possibly weaker, services.",
            evidence=f"{len(subs)} found, e.g. " + ", ".join(subs[:12]),
            recommendation="Review each subdomain; decommission unused hosts.",
            attack_surface=["Attack surface growth"], affected=root,
            check=f"external:{tool}",
        ))


def _run_nuclei(url, result):
    out = _exec(["nuclei", "-u", url, "-silent", "-severity",
                 "low,medium,high,critical", "-timeout", "5"], result)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("[")]
    if lines:
        sev = "high" if any("critical]" in l or "high]" in l for l in lines) \
            else "medium"
        result.add(Finding(
            title="Template-based findings (nuclei)", severity=sev,
            category="A06: Vulnerable & Outdated Components",
            cwe="CWE-1395: Dependency on Vulnerable Component",
            description="nuclei matched one or more vulnerability/exposure "
                        "templates against the target.",
            impact="Template matches often indicate known CVEs or exposures.",
            evidence="\n".join(lines[:30]),
            recommendation="Triage each match; patch or mitigate confirmed issues.",
            references=["https://github.com/projectdiscovery/nuclei"],
            affected=url, confidence="Medium", check="external:nuclei",
        ))


def _run_wpscan(url, result):
    out = _exec(["wpscan", "--url", url, "--no-banner", "--format", "cli-no-color",
                 "--random-user-agent"], result)
    flags = [ln.strip() for ln in out.splitlines()
             if "[!]" in ln or "vulnerabilit" in ln.lower()]
    if flags:
        result.add(Finding(
            title="WordPress issues reported by wpscan", severity="medium",
            category="A06: Vulnerable & Outdated Components",
            description="wpscan reported WordPress core/plugin/theme concerns.",
            impact="Outdated WordPress components are a common breach vector.",
            evidence="\n".join(flags[:25]),
            recommendation="Update WordPress core, plugins and themes; remove "
                           "unused ones.",
            references=["https://wpscan.com/"], affected=url, check="external:wpscan",
        ))


def _run_dirscan(cmd, result, tool):
    out = _exec(cmd, result)
    hits = [ln.strip() for ln in out.splitlines()
            if any(c in ln for c in ("200", "301", "302", "403")) and "/" in ln]
    if hits:
        result.add(Finding(
            title=f"Content discovery results ({tool})", severity="info",
            category="A05: Security Misconfiguration", cwe="CWE-200",
            description="Directory/content brute forcing located additional paths.",
            impact="Unlinked paths may expose admin or sensitive functionality.",
            evidence="\n".join(hits[:30]),
            recommendation="Review discovered paths; protect or remove sensitive "
                           "ones.",
            attack_surface=["Information disclosure"], affected=tool,
            check=f"external:{tool}",
        ))


def _run_simple(cmd, result, tool, title, severity, category):
    out = _exec(cmd, result)
    if not out.strip():
        return
    lines = [ln.rstrip() for ln in out.splitlines() if ln.strip()][:25]
    if lines:
        result.add(Finding(
            title=title, severity=severity, category=category,
            description=f"Output summary from {tool}.",
            impact="See evidence; interpret in context of the target.",
            evidence="\n".join(lines), recommendation="Review and act on relevant "
            "items.", affected=tool, check=f"external:{tool}",
        ))


def _looks_wordpress(result) -> bool:
    fp = result.meta.get("fingerprints", [])
    return any("wordpress" in str(x).lower() for x in fp)
