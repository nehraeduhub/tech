# Tech Guardians — Portable VAPT Portal

A **fully portable, database-free** Vulnerability Assessment & Penetration
Testing portal. Copy it to a USB stick, plug it into any machine with Python 3,
run one script, and a browser portal opens. Enter a target you are **authorised**
to test, and it runs non-intrusive security checks and generates a
**Tech Guardians–branded PDF report**.

> ⚠️ **Authorised use only.** Only scan systems you own or have **written
> permission** to test. Unauthorised scanning is illegal in most jurisdictions.
> The portal requires you to confirm authorisation before every scan, in line
> with responsible testing practice (e.g. CERT-In guidelines).

---

## Why "portable"?

- **No database.** Scan state lives in memory; each report is written as a
  self-contained `.pdf` + `.json` in `./reports/`.
- **No install step for the user.** `run.sh` / `run.bat` build a local
  virtualenv *on the stick* the first time, then launch.
- **Works offline.** All core checks are pure Python. Heavyweight open-source
  scanners are used **only if they already exist** on the host.

---

## Quick start

### Windows
Double-click **`run.bat`** (or run it from a terminal).

### Linux / macOS
```bash
chmod +x run.sh
./run.sh
```

The portal opens at **http://127.0.0.1:5000/**. Fill in the target and details,
tick the authorisation box, and click **Start Assessment**. When the scan
finishes you get an on-screen summary and a **Download PDF** button.

Manual launch (if you prefer):
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py
```

---

## What it checks (non-intrusive)

All checks use only safe GET/HEAD/OPTIONS requests and passive TLS/DNS
inspection — no exploitation, brute-forcing, injection payloads, or DoS.

| Area | Examples |
|------|----------|
| HTTP security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Cookies | Secure / HttpOnly / SameSite flags |
| TLS / SSL | protocol version, certificate validity & expiry |
| Information exposure | `.git`, `.env`, backups, `server-status`, directory listing |
| HTTP methods | dangerous methods (PUT/DELETE/TRACE) |
| DNS posture | records, SPF presence (email-spoofing context) |

### Optional open-source scanners (auto-detected)

If these well-known tools are installed on the host, the portal invokes them in
standard, conservative modes and folds a summary into the report:

- **[nmap](https://nmap.org/)** — service/port discovery
- **[nikto](https://github.com/sullo/nikto)** — web server misconfiguration
- **[testssl.sh](https://github.com/drwetter/testssl.sh)** — TLS auditing

If they are absent, the portal relies on its built-in checks — so it always runs.

---

## The report

Each assessment produces a branded PDF with:

1. **Cover** — target, client, assessor, engagement ref, overall risk score.
2. **Executive summary** — severity breakdown.
3. **Potential attack surface** — the classes of attack the findings could
   enable, for prioritisation (risk context, *not* exploitation guidance).
4. **Detailed findings** — description, evidence, remediation, references.
5. **Methodology & scope** — tools used, authorisation note, assessment log.

Reports are saved to `./reports/` as both `.pdf` and `.json`.

---

## Project layout

```
vapt-portal/
├── app.py                 # Flask portal (no DB)
├── run.sh / run.bat       # plug-and-run launchers
├── requirements.txt
├── scanner/
│   ├── engine.py          # orchestration
│   ├── models.py          # findings, scoring
│   └── checks/            # individual non-intrusive checks
├── report/
│   ├── pdf_generator.py   # Tech Guardians branded PDF
│   └── assets/logo.svg
├── templates/  static/    # portal UI
└── reports/               # generated output (gitignored)
```

---

## Scope & legal

This tool performs **vulnerability assessment** (finding and reporting
weaknesses). It is intended for security professionals operating under a valid
engagement. You are responsible for ensuring you have authorisation and for
complying with all applicable laws, regulations, and standards.
