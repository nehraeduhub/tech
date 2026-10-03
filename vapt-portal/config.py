"""Central branding & report configuration for the RJHex VAPT Portal.

Rebranding is a one-file job: change the values below (and replace the two
logo files in static/logo.svg and report/assets/logo.svg) and the whole portal
and every generated report update automatically.

The AUTHOR_MARK credit is a permanent attribution and is rendered on the portal
footer, the report cover, and every report page.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Brand identity  (edit these to rebrand)
# ---------------------------------------------------------------------------
BRAND_NAME = "RJHex"
BRAND_TAGLINE = "Vulnerability Assessment & Penetration Testing"
BRAND_SHORT = "RJHex Security"
BRAND_WEBSITE = ""          # optional, shown on report cover if set
BRAND_EMAIL = ""            # optional contact e-mail for the report

# Permanent authorship credit — do not remove.
AUTHOR_MARK = "Designed & Developed by Rajesh Nehra · Master in Cyber Security"
AUTHOR_NAME = "Rajesh Nehra"
AUTHOR_TITLE = "Master in Cyber Security"

# ---------------------------------------------------------------------------
# Colour palette (hex). Used by both the web UI and the PDF report.
# ---------------------------------------------------------------------------
COLOR_PRIMARY = "#0a1f44"   # deep navy
COLOR_ACCENT = "#e63946"    # RJHex red
COLOR_ACCENT2 = "#2a9d8f"   # teal (secondary)
COLOR_LIGHT = "#eef2f9"
COLOR_INK = "#16202e"

# ---------------------------------------------------------------------------
# Report metadata
# ---------------------------------------------------------------------------
REPORT_CLASSIFICATION = "CONFIDENTIAL"
REPORT_TITLE = "Security Assessment Report"
REPORT_DOC_PREFIX = "RJHEX"           # used in document reference IDs
REPORT_STANDARDS = [
    "OWASP Testing Guide (WSTG) v4.2",
    "OWASP Top 10 (2021)",
    "OWASP API Security Top 10",
    "NIST SP 800-115",
    "PTES (Penetration Testing Execution Standard)",
    "CERT-In guidance for security auditing",
]

# ---------------------------------------------------------------------------
# Engine defaults
# ---------------------------------------------------------------------------
DEFAULT_HTTP_TIMEOUT = 15
DEFAULT_ENABLE_ACTIVE_TOOLS = True   # active external tools if installed
DEFAULT_PORT_SCAN = True             # built-in TCP connect scan

# ---------------------------------------------------------------------------
# Access control & licensing
# ---------------------------------------------------------------------------
# 1) PORTAL LOGIN -----------------------------------------------------------
# Require a password to open the portal. Leave the hash empty to disable login.
# Generate a hash with:  python -c "import hashlib;print(hashlib.sha256(b'YOURPASS').hexdigest())"
LOGIN_REQUIRED = False
LOGIN_USERNAME = "admin"
LOGIN_PASSWORD_HASH = ""   # sha256 hex of your password (see command above)
# Session signing secret. Set a long random value in production; falls back to
# a per-start random key (logs everyone out on restart) if left blank.
SESSION_SECRET = ""

# 2) MACHINE-LOCKED LICENSE -------------------------------------------------
# When True, the portal refuses to start without a valid, signed, machine-bound
# license file. Set up keys with license_tool.py first (see SECURITY.md).
LICENSE_ENFORCE = False
LICENSE_FILE = "license.key"
# Paste the PUBLIC key printed by `python license_tool.py genkeys` here.
# The matching PRIVATE key stays with you and is NEVER shipped.
LICENSE_PUBLIC_KEY = ""
