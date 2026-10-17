"""Active web-vulnerability probes (penetration-testing detection layer).

These probes CONFIRM common web vulnerabilities by sending carefully chosen,
NON-DESTRUCTIVE test inputs and observing the response:

  * Reflected XSS      - benign marker, checks for unencoded reflection
  * SQL injection      - error signature, boolean differential, time delay
  * OS command inject. - time delay (sleep) only
  * Path traversal/LFI - reads a well-known read-only file signature
  * Open redirect      - checks a canary redirect target

What they DO NOT do: modify or delete data, run destructive commands, bypass
authentication, perform DoS, or exfiltrate real data. They only prove a weakness
exists so it can be fixed. Run only against systems you are authorised to test.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qs

import requests

from ..models import Finding

UA = "Tech Guardians-VAPT/3.0 (authorised security assessment)"
MARK = "tgx9z1"  # unique token so we recognise our own payloads

# ---- caps so a scan stays bounded and polite ----
MAX_PARAM_TARGETS = 30
MAX_FORM_TARGETS = 15
TIME_DELAY = 5           # seconds used by time-based probes
TIME_THRESHOLD = 4.0     # min extra latency to call a time-based hit

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark after the character string", "quoted string not "
    "properly terminated", "pg_query()", "postgresql query failed",
    "sqlite3::", "sqlite_error", "ora-01756", "ora-00933", "odbc sql server "
    "driver", "microsoft ole db provider for sql server", "syntax error at or near",
]
PASSWD_SIG = ("root:x:0:0:", "root:*:0:0:", "daemon:x:1:1:")


def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    return s


def _set_get_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    qs = parse_qs(parts.query)
    qs[param] = [value]
    flat = urlencode({k: v[0] for k, v in qs.items()})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, flat, ""))


def run(surface: dict, result, timeout: int = 12) -> None:
    """surface = {'get_params':[{url,params}], 'forms':[{action,method,inputs}]}."""
    result.mark_check("Active injection probes (XSS/SQLi/CMDi/LFI/redirect)")
    s = _session()

    # Build a flat list of (kind, url, method, param, base_params)
    targets = []
    for gp in surface.get("get_params", [])[:MAX_PARAM_TARGETS]:
        for p in gp["params"]:
            targets.append(("get", gp["url"], "get", p, gp["params"]))
    for fm in surface.get("forms", [])[:MAX_FORM_TARGETS]:
        for p in fm["inputs"]:
            base = {i: "test" for i in fm["inputs"]}
            targets.append(("form", fm["action"], fm["method"], p, base))

    if not targets:
        result.log("No parameters/forms discovered to probe for injection")
        return
    result.log(f"Probing {len(targets)} parameter(s) for injection flaws")

    tested = set()
    for kind, url, method, param, base in targets:
        sig = f"{method}:{url}:{param}"
        if sig in tested:
            continue
        tested.add(sig)
        try:
            _probe_xss(s, url, method, param, base, result, timeout)
            _probe_sqli(s, url, method, param, base, result, timeout)
            _probe_traversal(s, url, method, param, base, result, timeout)
            _probe_cmdi(s, url, method, param, base, result, timeout)
            if param.lower() in ("url", "next", "redirect", "return", "dest",
                                 "returnurl", "continue", "r", "u", "goto"):
                _probe_open_redirect(s, url, method, param, base, result, timeout)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"injection probe error on {param}: {exc}")


def _send(s, url, method, param, base, value, timeout, allow_redirects=True):
    if method == "post":
        data = dict(base)
        data[param] = value
        return s.post(url, data=data, timeout=timeout,
                      allow_redirects=allow_redirects, verify=True)
    target = _set_get_param(url, param, value)
    return s.get(target, timeout=timeout, allow_redirects=allow_redirects,
                 verify=True)


def _add(result, title, severity, cwe, cat, desc, impact, evidence, rec, attack,
         affected, param):
    result.add(Finding(
        title=title, severity=severity, cwe=cwe, category=cat, description=desc,
        impact=impact, evidence=evidence, recommendation=rec, attack_surface=attack,
        affected=f"{affected} (parameter: {param})", confidence="Confirmed",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        check="injection"))


def _probe_xss(s, url, method, param, base, result, timeout):
    payload = f'{MARK}"><svg/onload=alert({MARK})>'
    try:
        resp = _send(s, url, method, param, base, payload, timeout)
    except Exception:
        return
    if payload in (resp.text or ""):
        _add(result, "Reflected Cross-Site Scripting (XSS) — confirmed", "high",
             "CWE-79: Cross-site Scripting",
             "A03: Injection",
             "A crafted value is reflected into the response without encoding, "
             "allowing script injection.",
             "An attacker can run arbitrary JavaScript in victims' browsers "
             "(session theft, defacement, phishing).",
             f"Payload reflected unencoded at {url} via '{param}'.",
             "Context-encode all output; apply a strict Content-Security-Policy; "
             "validate input.",
             ["Cross-Site Scripting (XSS)", "Session hijacking"], url, param)


def _probe_sqli(s, url, method, param, base, result, timeout):
    # 1) error-based
    try:
        resp = _send(s, url, method, param, base, base.get(param, "1") + "'",
                     timeout)
        body = (resp.text or "").lower()
        for err in SQL_ERRORS:
            if err in body:
                _add(result, "SQL Injection — error-based (confirmed)", "critical",
                     "CWE-89: SQL Injection", "A03: Injection",
                     "A single quote triggers a database error, indicating unsanitised "
                     "input reaches an SQL query.",
                     "Full database compromise: read/modify data, auth bypass, "
                     "sometimes OS access.",
                     f"DB error signature '{err}' returned from {url} via '{param}'.",
                     "Use parameterised queries / prepared statements; never build "
                     "SQL from user input.",
                     ["SQL Injection", "Data breach", "Authentication bypass"],
                     url, param)
                return
    except Exception:
        pass
    # 2) boolean-based differential
    try:
        orig = base.get(param, "1")
        t = _send(s, url, method, param, base, f"{orig} AND 1=1", timeout)
        f = _send(s, url, method, param, base, f"{orig} AND 1=2", timeout)
        lt, lf = len(t.text or ""), len(f.text or "")
        if lt and lf and abs(lt - lf) > max(40, int(0.1 * lt)):
            _add(result, "SQL Injection — boolean-based (likely)", "high",
                 "CWE-89: SQL Injection", "A03: Injection",
                 "Responses differ measurably between a true and false SQL "
                 "condition, indicating injectable input.",
                 "Allows blind extraction of database contents.",
                 f"AND 1=1 vs AND 1=2 response sizes differ ({lt} vs {lf}) at {url} "
                 f"via '{param}'.",
                 "Use parameterised queries; validate and canonicalise input.",
                 ["Blind SQL Injection"], url, param)
            return
    except Exception:
        pass
    # 3) time-based
    try:
        base_resp = _send(s, url, method, param, base, base.get(param, "1"), timeout)
        t0 = base_resp.elapsed.total_seconds()
        payload = f"{base.get(param,'1')}' AND SLEEP({TIME_DELAY})-- -"
        start = time.time()
        _send(s, url, method, param, base, payload, timeout + TIME_DELAY + 2)
        elapsed = time.time() - start
        if elapsed - t0 >= TIME_THRESHOLD:
            _add(result, "SQL Injection — time-based blind (confirmed)", "critical",
                 "CWE-89: SQL Injection", "A03: Injection",
                 "A SLEEP() payload measurably delays the response, confirming "
                 "blind SQL injection.",
                 "Allows full blind extraction/modification of database data.",
                 f"SLEEP({TIME_DELAY}) delayed response by ~{elapsed:.1f}s at {url} "
                 f"via '{param}'.",
                 "Use parameterised queries / prepared statements.",
                 ["Blind SQL Injection", "Data breach"], url, param)
    except Exception:
        pass


def _probe_traversal(s, url, method, param, base, result, timeout):
    for payload in ("../../../../../../etc/passwd",
                    "....//....//....//....//etc/passwd"):
        try:
            resp = _send(s, url, method, param, base, payload, timeout)
            if any(sig in (resp.text or "") for sig in PASSWD_SIG):
                _add(result, "Path Traversal / Local File Inclusion — confirmed",
                     "high", "CWE-22: Path Traversal", "A01: Broken Access Control",
                     "A traversal sequence returns the contents of a system file.",
                     "Attackers can read source code, configuration and secrets; "
                     "sometimes escalate to code execution.",
                     f"/etc/passwd signature returned from {url} via '{param}'.",
                     "Reject path separators; use allow-lists; serve files by ID "
                     "from a fixed directory.",
                     ["Local File Inclusion", "Sensitive file disclosure"],
                     url, param)
                return
        except Exception:
            continue


def _probe_cmdi(s, url, method, param, base, result, timeout):
    base_val = base.get(param, "1")
    try:
        br = _send(s, url, method, param, base, base_val, timeout)
        t0 = br.elapsed.total_seconds()
    except Exception:
        t0 = 0.0
    for payload in (f"{base_val};sleep {TIME_DELAY}",
                    f"{base_val}|sleep {TIME_DELAY}",
                    f"{base_val}$(sleep {TIME_DELAY})"):
        try:
            start = time.time()
            _send(s, url, method, param, base, payload, timeout + TIME_DELAY + 2)
            elapsed = time.time() - start
            if elapsed - t0 >= TIME_THRESHOLD:
                _add(result, "OS Command Injection — time-based (confirmed)",
                     "critical", "CWE-78: OS Command Injection", "A03: Injection",
                     "A shell 'sleep' payload delays the response, indicating the "
                     "application passes input to a system command.",
                     "Full server compromise: arbitrary command execution.",
                     f"'sleep {TIME_DELAY}' delayed response by ~{elapsed:.1f}s at "
                     f"{url} via '{param}'.",
                     "Never pass user input to shells; use safe APIs and strict "
                     "allow-lists.",
                     ["Remote Command Execution", "Full server compromise"],
                     url, param)
                return
        except Exception:
            continue


def _probe_open_redirect(s, url, method, param, base, result, timeout):
    canary = "https://tg-oob-canary.example/"
    try:
        resp = _send(s, url, method, param, base, canary, timeout,
                     allow_redirects=False)
        loc = resp.headers.get("Location", "")
        if loc.startswith(canary) or loc.startswith("//tg-oob-canary.example"):
            _add(result, "Open Redirect — confirmed", "medium",
                 "CWE-601: Open Redirect", "A01: Broken Access Control",
                 "The application redirects to an attacker-supplied external URL.",
                 "Enables convincing phishing and can aid OAuth token theft.",
                 f"Redirected to canary URL from {url} via '{param}'.",
                 "Redirect only to a server-side allow-list of paths; never trust a "
                 "user-supplied URL.",
                 ["Phishing", "Open Redirect"], url, param)
    except Exception:
        pass
