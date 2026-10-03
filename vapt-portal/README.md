# Tech Guardians — Portable VAPT Portal

**Designed & Developed by Rajesh Nehra · Master in Cyber Security**

A **portable, database-free** Vulnerability Assessment & Penetration Testing
portal. Copy it to a USB stick, run one script on any machine with Python 3, and
a browser portal opens. Enter a target you are **authorised** to test and it runs
a wide battery of checks — built-in Python checks plus any installed Kali /
open-source tools — and generates a **detailed, professional, Tech Guardians-branded PDF
report**.

> ⚠️ **Authorised use only.** Only scan systems you own or have **written
> permission** to test. Unauthorised scanning is illegal. The portal requires you
> to confirm authorisation before every scan, in line with responsible testing
> practice (e.g. CERT-In guidance).

> ℹ️ **On "CERT-In certification":** CERT-In empanelment is granted to auditing
> *organisations*, not to tools. This portal cannot make anyone CERT-In
> certified. What it does is produce reports whose **structure and rigour match
> what empanelled auditors deliver** (methodology, CVSS/CWE/OWASP mapping,
> evidence, remediation roadmap, compliance mapping).

---

## Quick start

### Windows
Double-click **`run.bat`**.

### Linux / macOS
```bash
chmod +x run.sh
./run.sh
```

First launch builds a local virtualenv *on the stick* and installs Python deps
(needs internet once). The portal then opens at **http://127.0.0.1:5000/**.

---

## What it tests

### Built-in checks (pure Python, always run, non-intrusive)
- HTTP security headers (HSTS, CSP, X-Frame-Options, COOP, caching, …)
- Cookie flags (Secure / HttpOnly / SameSite)
- TLS/SSL — protocol version, certificate validity & expiry
- Information exposure — `.git`, `.env`, backups, admin panels, directory listing
- CORS misconfiguration (reflective, read-only)
- Content/technology analysis — mixed content, CMS fingerprint, outdated JS
  libraries, forms without CSRF tokens
- DNS & email security — SPF, DMARC, DKIM, CAA, DNSSEC
- Built-in TCP port scan of common ports
- WAF / CDN detection

### Optional external tools (auto-detected; see **TOOLS.md**)
nmap · nikto · nuclei · wpscan · wapiti · whatweb · wafw00f · sslscan ·
testssl.sh · sslyze · dnsrecon · subfinder · sublist3r · amass · gobuster ·
ffuf · dirb · feroxbuster — the portal uses whatever is on `PATH`. **Active**
tools (nuclei, wpscan, dir brute-force, wapiti) run only when you tick
*"Allow active tools"*.

👉 **Install list & commands: see [TOOLS.md](TOOLS.md).**

---

## The report (professional, detailed)

Each assessment produces a multi-section branded PDF:

1. **Cover** — target, client, risk score, security grade, author credit
2. **Document control** — reference, version, classification, legal notice
3. **Executive summary** — risk gauge, grade badge, severity chart, key themes
4. **Scope & methodology** — standards referenced (OWASP WSTG, NIST 800-115,
   PTES, CERT-In), severity model, checks performed
5. **Findings summary table** — ID, severity, CVSS, CWE, OWASP per finding
6. **Detailed findings** — description, impact, evidence, remediation, references
7. **Remediation roadmap** — prioritised by urgency (Immediate → Hardening)
8. **Compliance mapping** — OWASP Top 10 coverage
9. **Appendices** — tools used, full assessment log

Reports are saved to `./reports/` as `.pdf` + `.json`.

---

## Rebranding

Everything is driven by **`config.py`** — change `BRAND_NAME`, `BRAND_TAGLINE`,
colours, classification, etc., and replace the two logo files
(`static/logo.svg` and `report/assets/logo.svg`). The author credit
(`AUTHOR_MARK`) is a permanent attribution shown on the portal and every report
page.

---

## Project layout

```
vapt-portal/
├── config.py              # branding + report settings (edit to rebrand)
├── app.py                 # Flask portal (no DB)
├── run.sh / run.bat       # plug-and-run launchers
├── requirements.txt
├── TOOLS.md               # external tool install guide
├── scanner/
│   ├── engine.py
│   ├── models.py          # findings, CVSS/CWE, scoring, grade
│   └── checks/            # http_security, tls, cors, content, exposure,
│                          #   email_dns, ports, waf, external_tools
├── report/
│   ├── pdf_generator.py   # professional branded PDF
│   └── assets/logo.svg
├── templates/  static/    # portal UI
└── reports/               # generated output (gitignored)
```

---

## Legal & scope

This tool performs **vulnerability assessment** and authorised penetration
testing. You are responsible for holding authorisation and complying with all
applicable laws, regulations and standards.
