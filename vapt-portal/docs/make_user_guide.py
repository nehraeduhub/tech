#!/usr/bin/env python3
"""Generate the Tech Guardians VAPT Portal — User Guide PDF.

Run from the project root:  python docs/make_user_guide.py
Outputs: docs/TechGuardians_User_Guide.pdf
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem,
)

import config
from report.pdf_generator import _styles, _page_decoration, PRIMARY, ACCENT, LIGHT, INK

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "TechGuardians_User_Guide.pdf")


def code(txt, styles):
    """A monospaced command block."""
    t = Table([[Paragraph(txt.replace(" ", "&nbsp;").replace("\n", "<br/>"),
                          ParagraphStyle("code", fontName="Courier", fontSize=8.5,
                                         textColor=colors.white, leading=12))]],
              colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0d1b2a")),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
    ]))
    return t


def step_box(n, title, body, styles):
    """A numbered step row."""
    num = Table([[Paragraph(f"<b>{n}</b>", ParagraphStyle(
        "n", textColor=colors.white, fontSize=13, alignment=TA_CENTER))]],
        colWidths=[10 * mm], rowHeights=[10 * mm])
    num.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    inner = [Paragraph(f"<b>{title}</b>", styles["RJH2"])]
    inner += body
    t = Table([[num, inner]], colWidths=[12 * mm, None])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def build():
    styles = _styles()
    doc = BaseDocTemplate(
        OUT, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=22 * mm, bottomMargin=16 * mm,
        title=f"{config.BRAND_NAME} — User Guide", author=config.AUTHOR_NAME)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="m")
    doc.addPageTemplates([PageTemplate(id="g", frames=[frame],
                                       onPage=_page_decoration)])
    s = []

    # ---------- Cover ----------
    s.append(Spacer(1, 22 * mm))
    logo = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "report", "assets", "logo.svg")
    try:
        from svglib.svglib import svg2rlg
        dr = svg2rlg(logo)
        if dr:
            sc = (46 * mm) / dr.height
            dr.scale(sc, sc); dr.width *= sc; dr.height *= sc; dr.hAlign = "CENTER"
            s.append(dr)
    except Exception:
        pass
    s += [
        Spacer(1, 8 * mm),
        Paragraph(config.BRAND_NAME, styles["RJTitle"]),
        Paragraph(config.BRAND_TAGLINE, ParagraphStyle(
            "c", alignment=TA_CENTER, textColor=ACCENT, fontSize=12)),
        Spacer(1, 3 * mm), HRFlowable(width="55%", thickness=1.4, color=ACCENT),
        Spacer(1, 12 * mm),
        Paragraph("USER GUIDE", ParagraphStyle(
            "ug", alignment=TA_CENTER, textColor=INK, fontSize=20, leading=26,
            spaceAfter=8)),
        Spacer(1, 4 * mm),
        Paragraph("Step-by-step: install, log in, scan and report",
                  ParagraphStyle("ug2", alignment=TA_CENTER, textColor=colors.grey,
                                 fontSize=11)),
        Spacer(1, 16 * mm),
        Paragraph(f"Version 2.0 · {datetime.now().strftime('%B %Y')}",
                  ParagraphStyle("v", alignment=TA_CENTER, fontSize=10,
                                 textColor=INK)),
        Spacer(1, 4 * mm),
        Paragraph(f"<b>{config.AUTHOR_MARK}</b>", ParagraphStyle(
            "a", alignment=TA_CENTER, textColor=PRIMARY, fontSize=10)),
        PageBreak(),
    ]

    # ---------- 0. Contents ----------
    s.append(Paragraph("Contents", styles["RJH1"]))
    toc = ["1. Before you start", "2. Install & launch the portal",
           "3. Set a login password (securing access)",
           "4. Log in", "5. Run your first assessment",
           "6. Read & download the report",
           "7. Lock the tool to your machines (licensing)",
           "8. Rebrand (name & logo)", "9. Install extra VAPT tools",
           "10. Troubleshooting & FAQ", "11. Legal & authorised use"]
    s.append(ListFlowable([ListItem(Paragraph(t, styles["RJBody"])) for t in toc],
                          bulletType="bullet", start="square"))
    s.append(PageBreak())

    # ---------- 1. Before you start ----------
    s.append(Paragraph("1. Before you start", styles["RJH1"]))
    s.append(Paragraph("You need:", styles["RJBody"]))
    s.append(ListFlowable([
        ListItem(Paragraph("A Windows, Linux or macOS computer.", styles["RJBody"])),
        ListItem(Paragraph("<b>Python 3.9+</b> installed (tick <i>Add Python to "
                           "PATH</i> on Windows).", styles["RJBody"])),
        ListItem(Paragraph("Internet access the first time (to install "
                           "dependencies) and to scan targets.", styles["RJBody"])),
        ListItem(Paragraph("<b>Written authorisation</b> to test any target.",
                           styles["RJBody"])),
    ], bulletType="bullet"))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("The tool is portable and needs no database — you can run "
                       "it from a USB stick. Reports are saved in the "
                       "<b>reports/</b> folder.", styles["RJBody"]))
    s.append(PageBreak())

    # ---------- 2. Install & launch ----------
    s.append(Paragraph("2. Install & launch the portal", styles["RJH1"]))
    s.append(step_box("1", "Copy the folder", [
        Paragraph("Unzip the tool anywhere — e.g. your USB stick or Desktop.",
                  styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("2", "Run the launcher", [
        Paragraph("<b>Windows:</b> double-click <b>run.bat</b>.", styles["RJBody"]),
        Paragraph("<b>Linux / macOS:</b> open a terminal in the folder and run:",
                  styles["RJBody"]), code("chmod +x run.sh\n./run.sh", styles)],
        styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("3", "Wait for first-time setup", [
        Paragraph("The first launch creates a local environment and installs "
                  "dependencies (one minute, needs internet). Later launches are "
                  "instant.", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("4", "Open the portal", [
        Paragraph("Your browser opens automatically at:", styles["RJBody"]),
        code("http://127.0.0.1:5000/", styles),
        Paragraph("If not, type that address into your browser.",
                  styles["RJSmall"])], styles))
    s.append(PageBreak())

    # ---------- 3. Set login password ----------
    s.append(Paragraph("3. Set a login password (securing access)", styles["RJH1"]))
    s.append(Paragraph("By default the portal opens without a password. To require "
                       "a login so only you can use it, do this once:",
                       styles["RJBody"]))
    s.append(Spacer(1, 2 * mm))
    s.append(step_box("1", "Create a password hash", [
        Paragraph("Open a terminal in the tool folder and run (replace "
                  "<i>MyStrongPass</i>):", styles["RJBody"]),
        code('python -c "import hashlib;print(hashlib.sha256('
             "b'MyStrongPass').hexdigest())\"", styles),
        Paragraph("Copy the long line it prints.", styles["RJSmall"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("2", "Edit config.py", [
        Paragraph("Open <b>config.py</b> and set these values:", styles["RJBody"]),
        code('LOGIN_REQUIRED      = True\n'
             'LOGIN_USERNAME      = "admin"\n'
             'LOGIN_PASSWORD_HASH = "<paste the hash here>"\n'
             'SESSION_SECRET      = "any-long-random-text"', styles)], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("3", "Restart the portal", [
        Paragraph("Close and re-launch. The portal now shows a sign-in page. Your "
                  "password is stored only as a hash, never in plain text.",
                  styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("<b>Tip —</b> to change the password later, repeat step 1 "
                       "with a new password and replace the hash. To turn login "
                       "off again, set <b>LOGIN_REQUIRED = False</b>.",
                       styles["RJSmall"]))
    s.append(PageBreak())

    # ---------- 4. Log in ----------
    s.append(Paragraph("4. Log in", styles["RJH1"]))
    s.append(step_box("1", "Enter credentials", [
        Paragraph("On the sign-in page, type the username (default "
                  "<b>admin</b>) and your password, then click <b>Sign in</b>.",
                  styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("2", "You're in", [
        Paragraph("You land on the assessment page. A <b>Log out</b> button appears "
                  "top-right; use it when you finish.", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("Forgot the password? You can't recover a hash — just set a "
                       "new one (section 3).", styles["RJSmall"]))
    s.append(PageBreak())

    # ---------- 5. Run assessment ----------
    s.append(Paragraph("5. Run your first assessment", styles["RJH1"]))
    s.append(step_box("1", "Enter the target", [
        Paragraph("Type the website or host, e.g. <b>example.com</b> or "
                  "<b>https://example.com</b>.", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("2", "Fill engagement details (optional)", [
        Paragraph("Client / Organisation, Assessor and Engagement Ref appear on the "
                  "report cover.", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("3", "Choose scan options", [
        Paragraph("Tick which to include: installed open-source/Kali tools, the "
                  "built-in port scan, and whether to allow <b>active</b> tools "
                  "(more thorough, more intrusive).", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("4", "Confirm authorisation", [
        Paragraph("Tick the box confirming you have written permission to test the "
                  "target. <b>The scan will not start otherwise.</b>",
                  styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("5", "Start", [
        Paragraph("Click <b>Start Assessment</b>. A live progress page shows each "
                  "step; it moves to the results automatically when finished.",
                  styles["RJBody"])], styles))
    s.append(PageBreak())

    # ---------- 6. Report ----------
    s.append(Paragraph("6. Read & download the report", styles["RJH1"]))
    s.append(Paragraph("The results page shows the overall risk rating, a security "
                       "grade (A–F), a severity breakdown and every finding with "
                       "remediation advice.", styles["RJBody"]))
    s.append(Spacer(1, 2 * mm))
    s.append(ListFlowable([
        ListItem(Paragraph("<b>Download PDF</b> — the full branded report.",
                           styles["RJBody"])),
        ListItem(Paragraph("<b>JSON</b> — machine-readable data.",
                           styles["RJBody"])),
        ListItem(Paragraph("Both are also saved automatically in the "
                           "<b>reports/</b> folder.", styles["RJBody"])),
    ], bulletType="bullet"))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("The PDF contains: cover, document control, executive "
                       "summary with charts, scope & methodology, findings summary "
                       "table, detailed findings (with CVSS, CWE, OWASP mapping, "
                       "evidence and remediation), a remediation roadmap, OWASP "
                       "compliance mapping and appendices.", styles["RJBody"]))
    s.append(PageBreak())

    # ---------- 7. Licensing ----------
    s.append(Paragraph("7. Lock the tool to your machines (licensing)",
                       styles["RJH1"]))
    s.append(Paragraph("Optional: bind the tool so it only runs on machines you "
                       "authorise, using signed licenses. You keep a secret key; "
                       "nobody can make a valid license without it.",
                       styles["RJBody"]))
    s.append(Spacer(1, 2 * mm))
    s.append(step_box("1", "Create your signing keys (once)", [
        code("python license_tool.py genkeys", styles),
        Paragraph("Keep <b>rjhex_private.key</b> secret. Paste the printed public "
                  "key into <b>config.py</b> → LICENSE_PUBLIC_KEY, and set "
                  "<b>LICENSE_ENFORCE = True</b>.", styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("2", "Get the user's machine code", [
        Paragraph("On the machine that will run the tool:", styles["RJBody"]),
        code("python license_tool.py fingerprint", styles)], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(step_box("3", "Issue a license", [
        code("python license_tool.py issue --licensee \"Acme\" \\\n"
             "   --fingerprint <code> --days 365 \\\n"
             "   --private rjhex_private.key --out license.key", styles),
        Paragraph("Send <b>license.key</b> to the user; they place it next to "
                  "app.py. It works only on that machine, until it expires.",
                  styles["RJBody"])], styles))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("Full details, and how to compile to a single .exe for "
                       "stronger protection, are in <b>SECURITY.md</b>.",
                       styles["RJSmall"]))
    s.append(PageBreak())

    # ---------- 8. Rebrand ----------
    s.append(Paragraph("8. Rebrand (name & logo)", styles["RJH1"]))
    s.append(ListFlowable([
        ListItem(Paragraph("Edit <b>config.py</b> — change BRAND_NAME, tagline, "
                           "colours and report settings.", styles["RJBody"])),
        ListItem(Paragraph("Replace the logo in BOTH <b>static/logo.svg</b> and "
                           "<b>report/assets/logo.svg</b> (same file).",
                           styles["RJBody"])),
        ListItem(Paragraph("Use an <b>SVG with solid colours</b> (no gradients) so "
                           "it renders in the PDF.", styles["RJBody"])),
        ListItem(Paragraph("Match <b>static/style.css</b> <i>:root</i> colours to "
                           "your config colours.", styles["RJBody"])),
    ], bulletType="bullet"))
    s.append(Spacer(1, 3 * mm))
    s.append(Paragraph("The author credit at the bottom of every page is set by "
                       "AUTHOR_MARK in config.py.", styles["RJSmall"]))

    # ---------- 9. Tools ----------
    s.append(Paragraph("9. Install extra VAPT tools", styles["RJH1"]))
    s.append(Paragraph("The portal auto-detects installed open-source / Kali tools "
                       "and uses whatever is present (nmap, nikto, nuclei, wpscan, "
                       "whatweb, wafw00f, sslscan, testssl.sh, subfinder, gobuster, "
                       "ffuf and more). Example on Kali:", styles["RJBody"]))
    s.append(code("sudo apt update && sudo apt install -y nmap nikto whatweb \\\n"
                  "  wafw00f dnsrecon sslscan testssl.sh dirb wapiti amass wpscan",
                  styles))
    s.append(Paragraph("The full install list (Linux/macOS/Windows) is in "
                       "<b>TOOLS.md</b>. Installed tools show a green ✓ on the home "
                       "page.", styles["RJSmall"]))
    s.append(PageBreak())

    # ---------- 10. Troubleshooting ----------
    s.append(Paragraph("10. Troubleshooting & FAQ", styles["RJH1"]))
    faq = [
        ("The browser didn't open", "Go to http://127.0.0.1:5000/ manually. If the "
         "port is busy, set TG_PORT to another value before launching."),
        ("\"Python was not found\"", "Install Python 3 and tick <i>Add to PATH</i> "
         "(Windows), then re-run the launcher."),
        ("A scan shows errors / few findings", "The target may block requests, or "
         "you're offline. Errors are listed in the report appendix; built-in checks "
         "still run even if external tools are absent."),
        ("I forgot my login password", "Passwords are stored as a hash and can't be "
         "recovered — set a new one (section 3)."),
        ("\"LICENSE CHECK FAILED\"", "The machine isn't licensed or the license "
         "expired. Run the fingerprint command and request a new license."),
        ("Logo missing in the PDF", "Use an SVG with solid fills — gradients don't "
         "render in the PDF."),
    ]
    rows = [[Paragraph(f"<b>{q}</b>", styles["RJCell"]),
             Paragraph(a, styles["RJCell"])] for q, a in faq]
    t = Table(rows, colWidths=[52 * mm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    s.append(t)
    s.append(PageBreak())

    # ---------- 11. Legal ----------
    s.append(Paragraph("11. Legal & authorised use", styles["RJH1"]))
    s.append(Paragraph("This tool performs vulnerability assessment and authorised "
                       "penetration testing. Scan only systems you own or have "
                       "<b>written permission</b> to test. Unauthorised scanning is "
                       "illegal in most jurisdictions. You are responsible for "
                       "holding authorisation and complying with all applicable "
                       "laws, regulations and standards (e.g. CERT-In guidance).",
                       styles["RJBody"]))
    s.append(Spacer(1, 4 * mm))
    s.append(Paragraph("Note on certification: CERT-In empanelment is granted to "
                       "auditing organisations, not to software. This tool produces "
                       "reports at a professional standard but cannot by itself "
                       "make anyone CERT-In certified.", styles["RJSmall"]))
    s.append(Spacer(1, 8 * mm))
    s.append(HRFlowable(width="100%", thickness=0.6, color=ACCENT))
    s.append(Paragraph(f"<b>{config.AUTHOR_MARK}</b>", ParagraphStyle(
        "end", alignment=TA_CENTER, textColor=PRIMARY, fontSize=10)))
    s.append(Paragraph(f"— {config.BRAND_NAME} · User Guide —", ParagraphStyle(
        "e2", alignment=TA_CENTER, textColor=colors.grey, fontSize=8)))

    doc.build(s)
    print("Wrote", OUT)


if __name__ == "__main__":
    build()
