"""RJHex branded, professional VAPT PDF report generator (pure reportlab)."""
from __future__ import annotations

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing, Rect, String, Circle
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, ListFlowable, ListItem,
)

import config

PRIMARY = colors.HexColor(config.COLOR_PRIMARY)
ACCENT = colors.HexColor(config.COLOR_ACCENT)
ACCENT2 = colors.HexColor(config.COLOR_ACCENT2)
LIGHT = colors.HexColor(config.COLOR_LIGHT)
INK = colors.HexColor(config.COLOR_INK)

SEV_COLORS = {
    "critical": colors.HexColor("#b00020"),
    "high": colors.HexColor("#e2571e"),
    "medium": colors.HexColor("#e0a800"),
    "low": colors.HexColor("#2a9d8f"),
    "info": colors.HexColor("#5a6470"),
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


# --------------------------------------------------------------------------- #
# Styles
# --------------------------------------------------------------------------- #
def _styles():
    ss = getSampleStyleSheet()
    add = ss.add
    add(ParagraphStyle("RJTitle", parent=ss["Title"], textColor=PRIMARY,
                       fontSize=28, leading=32))
    add(ParagraphStyle("RJH1", parent=ss["Heading1"], textColor=PRIMARY,
                       fontSize=16, spaceBefore=14, spaceAfter=6))
    add(ParagraphStyle("RJH2", parent=ss["Heading2"], textColor=ACCENT,
                       fontSize=12.5, spaceBefore=10, spaceAfter=4))
    add(ParagraphStyle("RJBody", parent=ss["BodyText"], textColor=INK,
                       fontSize=9.5, leading=14, alignment=TA_JUSTIFY))
    add(ParagraphStyle("RJSmall", parent=ss["BodyText"], textColor=colors.grey,
                       fontSize=8, leading=11))
    add(ParagraphStyle("RJCellH", parent=ss["BodyText"], textColor=colors.white,
                       fontSize=9, leading=12))
    add(ParagraphStyle("RJCell", parent=ss["BodyText"], textColor=INK,
                       fontSize=8.8, leading=12))
    return ss


# --------------------------------------------------------------------------- #
# Page furniture (header / footer with permanent author mark)
# --------------------------------------------------------------------------- #
def _page_decoration(canvas, doc):
    canvas.saveState()
    w, h = A4
    # Header band
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, h - 16 * mm, w, 16 * mm, fill=1, stroke=0)
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 16 * mm, 6 * mm, 16 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(12 * mm, h - 11 * mm, config.BRAND_NAME)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(w - 12 * mm, h - 11 * mm,
                           f"{config.REPORT_CLASSIFICATION} — {config.REPORT_TITLE}")
    # Footer
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(0.6)
    canvas.line(12 * mm, 13 * mm, w - 12 * mm, 13 * mm)
    canvas.setFillColor(PRIMARY)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawString(12 * mm, 9 * mm, config.AUTHOR_MARK)
    canvas.setFillColor(colors.grey)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(w - 12 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


# --------------------------------------------------------------------------- #
# Charts
# --------------------------------------------------------------------------- #
def _severity_bar(counts) -> Drawing:
    d = Drawing(460, 160)
    data = [[counts.get(s, 0) for s in SEV_ORDER]]
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 30, 20, 400, 120
    bc.data = data
    bc.barWidth = 10
    bc.groupSpacing = 18
    bc.valueAxis.valueMin = 0
    maxv = max([1] + data[0])
    bc.valueAxis.valueMax = maxv
    bc.valueAxis.valueStep = max(1, maxv // 5)
    bc.categoryAxis.categoryNames = [s.capitalize() for s in SEV_ORDER]
    bc.categoryAxis.labels.fontSize = 8
    for i, s in enumerate(SEV_ORDER):
        bc.bars[(0, i)].fillColor = SEV_COLORS[s]
    bc.bars.strokeColor = None
    d.add(bc)
    return d


def _risk_gauge(score: float, rating: str) -> Drawing:
    d = Drawing(170, 130)
    col = (SEV_COLORS["critical"] if score >= 80 else
           SEV_COLORS["high"] if score >= 60 else
           SEV_COLORS["medium"] if score >= 35 else
           SEV_COLORS["low"] if score >= 10 else SEV_COLORS["info"])
    d.add(Circle(85, 70, 48, fillColor=LIGHT, strokeColor=col, strokeWidth=6))
    d.add(String(85, 74, str(score), fontSize=26, fillColor=col,
                 textAnchor="middle", fontName="Helvetica-Bold"))
    d.add(String(85, 58, "/ 100", fontSize=9, fillColor=INK, textAnchor="middle"))
    d.add(String(85, 14, rating.upper(), fontSize=11, fillColor=col,
                 textAnchor="middle", fontName="Helvetica-Bold"))
    return d


def _grade_badge(grade: str) -> Drawing:
    d = Drawing(70, 70)
    palette = {"A": "#2a9d8f", "B": "#5aa84b", "C": "#e0a800",
               "D": "#e2571e", "E": "#d1391c", "F": "#b00020"}
    col = colors.HexColor(palette.get(grade, "#5a6470"))
    d.add(Rect(5, 5, 60, 60, rx=8, ry=8, fillColor=col, strokeColor=None))
    d.add(String(35, 22, grade, fontSize=34, fillColor=colors.white,
                 textAnchor="middle", fontName="Helvetica-Bold"))
    return d


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _chip(sev, w=22 * mm):
    t = Table([[Paragraph(f"<b>{sev.upper()}</b>",
                          ParagraphStyle("c", textColor=colors.white, fontSize=8,
                                         alignment=TA_CENTER))]], colWidths=[w])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS.get(sev, colors.grey)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


# --------------------------------------------------------------------------- #
# Main builder
# --------------------------------------------------------------------------- #
def build_report(result_dict, output_path, client_name="", assessor="",
                 engagement_ref="", scope_note="") -> str:
    styles = _styles()
    doc = BaseDocTemplate(
        output_path, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=22 * mm, bottomMargin=16 * mm,
        title=f"{config.BRAND_NAME} {config.REPORT_TITLE}",
        author=config.AUTHOR_NAME,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="m")
    doc.addPageTemplates([PageTemplate(id="rj", frames=[frame],
                                       onPage=_page_decoration)])

    s = []
    s += _cover(result_dict, styles, client_name, assessor, engagement_ref)
    s.append(PageBreak())
    s += _doc_control(result_dict, styles, client_name, assessor, engagement_ref)
    s += _toc(styles)
    s.append(PageBreak())
    s += _exec_summary(result_dict, styles)
    s.append(PageBreak())
    s += _scope_methodology(result_dict, styles, scope_note)
    s.append(PageBreak())
    s += _findings_summary_table(result_dict, styles)
    s.append(PageBreak())
    s += _detailed_findings(result_dict, styles)
    s += _remediation_roadmap(result_dict, styles)
    s.append(PageBreak())
    s += _compliance(result_dict, styles)
    s += _appendix(result_dict, styles)
    doc.build(s)
    return output_path


def _cover(r, styles, client, assessor, ref):
    flow = [Spacer(1, 18 * mm)]
    logo = os.path.join(os.path.dirname(__file__), "assets", "logo.svg")
    try:
        from svglib.svglib import svg2rlg  # type: ignore
        dr = svg2rlg(logo)
        if dr:
            scale = (38 * mm) / dr.height
            dr.scale(scale, scale); dr.width *= scale; dr.height *= scale
            dr.hAlign = "CENTER"
            flow.append(dr)
    except Exception:  # noqa: BLE001
        pass
    flow += [
        Spacer(1, 8 * mm),
        Paragraph(config.BRAND_NAME, styles["RJTitle"]),
        Paragraph(config.BRAND_TAGLINE, ParagraphStyle(
            "cs", alignment=TA_CENTER, textColor=ACCENT, fontSize=12)),
        Spacer(1, 3 * mm),
        HRFlowable(width="55%", thickness=1.4, color=ACCENT),
        Spacer(1, 14 * mm),
        Paragraph(config.REPORT_TITLE, ParagraphStyle(
            "rt", alignment=TA_CENTER, textColor=INK, fontSize=18)),
        Spacer(1, 10 * mm),
    ]
    meta = [
        ["Target", r.get("normalized_url", r.get("target", "—"))],
        ["Client / Organisation", client or "—"],
        ["Assessor", assessor or config.BRAND_SHORT],
        ["Engagement Reference", ref or _auto_ref()],
        ["Overall Risk", f"{r.get('risk_rating','—')} "
                         f"(score {r.get('risk_score','—')}/100)"],
        ["Security Grade", r.get("security_grade", "—")],
        ["Report Date", datetime.now().strftime("%d %B %Y")],
        ["Classification", config.REPORT_CLASSIFICATION],
    ]
    t = Table(meta, colWidths=[48 * mm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PRIMARY),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(t)
    flow += [
        Spacer(1, 12 * mm),
        Paragraph(f"<b>{_esc(config.AUTHOR_MARK)}</b>", ParagraphStyle(
            "auth", alignment=TA_CENTER, textColor=PRIMARY, fontSize=10)),
        Spacer(1, 4 * mm),
        Paragraph("This document is confidential and intended solely for the named "
                  "client. It describes weaknesses identified during an "
                  "<b>authorised</b> security assessment and must be handled on a "
                  "strict need-to-know basis.", styles["RJSmall"]),
    ]
    return flow


def _doc_control(r, styles, client, assessor, ref):
    flow = [Paragraph("Document Control", styles["RJH1"])]
    rows = [
        ["Field", "Detail"],
        ["Document title", f"{config.BRAND_NAME} {config.REPORT_TITLE}"],
        ["Document reference", ref or _auto_ref()],
        ["Version", "1.0"],
        ["Prepared by", assessor or config.BRAND_SHORT],
        ["Author / Developer", f"{config.AUTHOR_NAME} ({config.AUTHOR_TITLE})"],
        ["Client", client or "—"],
        ["Date of report", datetime.now().strftime("%d %B %Y")],
        ["Classification", config.REPORT_CLASSIFICATION],
        ["Distribution", "Named client only"],
    ]
    t = Table(rows, colWidths=[52 * mm, None])
    t.setStyle(_grid_style())
    flow.append(t)
    flow.append(Spacer(1, 6 * mm))
    flow.append(Paragraph("Confidentiality & Legal Notice", styles["RJH2"]))
    flow.append(Paragraph(
        "This assessment was performed only after confirmation of written "
        "authorisation to test the in-scope systems. The findings reflect the "
        "state of the target at the time of testing and do not guarantee the "
        "absence of other vulnerabilities. Testing of systems without explicit "
        "authorisation is illegal.", styles["RJBody"]))
    return flow


def _toc(styles):
    items = [
        "1. Executive Summary", "2. Scope & Methodology",
        "3. Findings Summary", "4. Detailed Findings",
        "5. Remediation Roadmap", "6. Compliance Mapping",
        "7. Appendices",
    ]
    flow = [Spacer(1, 6 * mm), Paragraph("Table of Contents", styles["RJH1"])]
    flow.append(ListFlowable(
        [ListItem(Paragraph(i, styles["RJBody"]), leftIndent=6) for i in items],
        bulletType="bullet", start="square"))
    return flow


def _exec_summary(r, styles):
    counts = r.get("severity_counts", {})
    total = sum(counts.values())
    flow = [Paragraph("1. Executive Summary", styles["RJH1"])]
    flow.append(Paragraph(
        f"{config.BRAND_SHORT} performed an automated vulnerability assessment and "
        f"penetration test against <b>{_esc(r.get('normalized_url','the target'))}"
        f"</b>. The engagement combined passive reconnaissance, configuration "
        f"review and, where authorised, active scanning using industry-standard "
        f"open-source tooling. A total of <b>{total}</b> finding(s) were "
        f"identified, producing an overall risk rating of "
        f"<b>{r.get('risk_rating','—')}</b> and a security grade of "
        f"<b>{r.get('security_grade','—')}</b>.", styles["RJBody"]))
    flow.append(Spacer(1, 4 * mm))

    # Gauge + grade + counts side by side
    counts_tbl = _counts_table(counts)
    layout = Table([[_risk_gauge(r.get("risk_score", 0), r.get("risk_rating", "—")),
                     _grade_badge(r.get("security_grade", "—")), counts_tbl]],
                   colWidths=[46 * mm, 26 * mm, None])
    layout.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    flow.append(layout)
    flow.append(Spacer(1, 4 * mm))
    flow.append(Paragraph("Severity Distribution", styles["RJH2"]))
    flow.append(_severity_bar(counts))

    flow.append(Paragraph("Key Risk Themes", styles["RJH2"]))
    top = [f for f in r.get("findings", []) if f["severity"] in
           ("critical", "high")][:5]
    if top:
        flow.append(ListFlowable(
            [ListItem(Paragraph(f"<b>{_esc(f['title'])}</b> — {_esc(f['category'])}",
                                styles["RJBody"])) for f in top],
            bulletType="bullet"))
    else:
        flow.append(Paragraph("No critical or high-risk issues were identified. "
                              "Lower-severity hardening items remain; see the "
                              "detailed findings.", styles["RJBody"]))
    return flow


def _counts_table(counts):
    rows = [[Paragraph(f"<b>{s.capitalize()}</b>", ParagraphStyle(
        "x", textColor=colors.white, fontSize=9)),
        Paragraph(f"<b>{counts.get(s,0)}</b>", ParagraphStyle(
            "y", textColor=colors.white, fontSize=9, alignment=TA_CENTER))]
        for s in SEV_ORDER]
    t = Table(rows, colWidths=[30 * mm, 14 * mm])
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 4),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    for i, s in enumerate(SEV_ORDER):
        style.append(("BACKGROUND", (0, i), (-1, i), SEV_COLORS[s]))
    t.setStyle(TableStyle(style))
    return t


def _scope_methodology(r, styles, scope_note):
    flow = [Paragraph("2. Scope & Methodology", styles["RJH1"])]
    flow.append(Paragraph("2.1 Scope", styles["RJH2"]))
    flow.append(Paragraph(
        f"In-scope target: <b>{_esc(r.get('normalized_url','—'))}</b>. "
        + (_esc(scope_note) if scope_note else
           "Testing was limited to the single authorised target host and its "
           "directly associated web surface."), styles["RJBody"]))

    flow.append(Paragraph("2.2 Methodology", styles["RJH2"]))
    flow.append(Paragraph(
        "The assessment followed a recognised methodology combining passive and "
        "active techniques: reconnaissance and fingerprinting, transport security "
        "review, HTTP security-control review, information-exposure testing, DNS "
        "and email-security posture, and (where authorised) active scanning with "
        "open-source tooling. The approach aligns with the following references:",
        styles["RJBody"]))
    flow.append(ListFlowable(
        [ListItem(Paragraph(_esc(std), styles["RJBody"]))
         for std in config.REPORT_STANDARDS], bulletType="bullet"))

    flow.append(Paragraph("2.3 Severity Model", styles["RJH2"]))
    flow.append(Paragraph(
        "Findings are rated Critical / High / Medium / Low / Informational, "
        "indicatively aligned to CVSS v3.1 base-score bands (Critical ≥9.0, "
        "High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). Each finding carries a CWE "
        "reference and an OWASP category where applicable.", styles["RJBody"]))

    flow.append(Paragraph("2.4 Checks Performed", styles["RJH2"]))
    checks = r.get("checks_run", [])
    if checks:
        flow.append(ListFlowable(
            [ListItem(Paragraph(_esc(c), styles["RJBody"])) for c in checks],
            bulletType="bullet"))
    return flow


def _findings_summary_table(r, styles):
    flow = [Paragraph("3. Findings Summary", styles["RJH1"])]
    findings = r.get("findings", [])
    if not findings:
        flow.append(Paragraph("No findings were produced by the automated checks.",
                              styles["RJBody"]))
        return flow
    header = [Paragraph(f"<b>{h}</b>", styles["RJCellH"])
              for h in ("ID", "Finding", "Severity", "CVSS", "CWE", "OWASP")]
    rows = [header]
    for i, f in enumerate(findings, 1):
        rows.append([
            Paragraph(f"F-{i:02d}", styles["RJCell"]),
            Paragraph(_esc(f["title"]), styles["RJCell"]),
            Paragraph(f["severity"].upper(), ParagraphStyle(
                "sv", fontSize=8.5, textColor=SEV_COLORS[f["severity"]],
                fontName="Helvetica-Bold")),
            Paragraph(str(f.get("cvss_score", "—")), styles["RJCell"]),
            Paragraph(_esc((f.get("cwe", "") or "—").split(":")[0]), styles["RJCell"]),
            Paragraph(_esc(f.get("category", "—").split(":")[0]), styles["RJCell"]),
        ])
    t = Table(rows, colWidths=[14 * mm, None, 18 * mm, 13 * mm, 22 * mm, 18 * mm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
    ]))
    flow.append(t)
    return flow


def _detailed_findings(r, styles):
    flow = [Paragraph("4. Detailed Findings", styles["RJH1"])]
    findings = r.get("findings", [])
    if not findings:
        flow.append(Paragraph("No findings to detail. A manual review is still "
                              "recommended.", styles["RJBody"]))
        return flow
    for i, f in enumerate(findings, 1):
        flow.append(Spacer(1, 3 * mm))
        head = Table([[Paragraph(f"<b>F-{i:02d}  {_esc(f['title'])}</b>",
                                 styles["RJH2"]), _chip(f["severity"])]],
                     colWidths=[None, 24 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        flow.append(head)
        detail = [
            ["Severity / CVSS", f"{f['severity'].upper()} · "
             f"{f.get('cvss_score','—')}/10"
             + (f"  ({f['cvss_vector']})" if f.get("cvss_vector") else "")],
            ["Confidence", f.get("confidence", "—")],
            ["OWASP Category", f.get("category", "—")],
            ["CWE", f.get("cwe", "—") or "—"],
            ["Affected", f.get("affected", "") or r.get("normalized_url", "—")],
            ["Description", _esc(f.get("description", ""))],
        ]
        if f.get("impact"):
            detail.append(["Impact", _esc(f["impact"])])
        if f.get("evidence"):
            detail.append(["Evidence", _esc(f["evidence"])])
        if f.get("attack_surface"):
            detail.append(["Could enable", ", ".join(f["attack_surface"])])
        if f.get("recommendation"):
            detail.append(["Remediation", _esc(f["recommendation"])])
        if f.get("references"):
            detail.append(["References", "<br/>".join(_esc(x)
                           for x in f["references"])])
        rows = [[Paragraph(f"<b>{k}</b>", styles["RJCell"]),
                 Paragraph(v, styles["RJCell"])] for k, v in detail]
        t = Table(rows, colWidths=[32 * mm, None])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), LIGHT),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(t)
    return flow


def _remediation_roadmap(r, styles):
    flow = [PageBreak(), Paragraph("5. Remediation Roadmap", styles["RJH1"])]
    findings = r.get("findings", [])
    buckets = {
        "Immediate (0–7 days)": [f for f in findings if f["severity"] == "critical"],
        "Short term (1–4 weeks)": [f for f in findings if f["severity"] == "high"],
        "Medium term (1–3 months)": [f for f in findings if f["severity"] == "medium"],
        "Hardening (backlog)": [f for f in findings if f["severity"] in
                                ("low", "info")],
    }
    for phase, items in buckets.items():
        if not items:
            continue
        flow.append(Paragraph(phase, styles["RJH2"]))
        flow.append(ListFlowable(
            [ListItem(Paragraph(
                f"<b>{_esc(f['title'])}</b>: {_esc(f.get('recommendation','') )}",
                styles["RJBody"])) for f in items[:12]], bulletType="bullet"))
    if not findings:
        flow.append(Paragraph("No remediation actions required from automated "
                              "testing.", styles["RJBody"]))
    return flow


def _compliance(r, styles):
    flow = [Paragraph("6. Compliance Mapping (OWASP Top 10)", styles["RJH1"])]
    cov = r.get("owasp_coverage", {})
    rows = [[Paragraph("<b>Category</b>", styles["RJCellH"]),
             Paragraph("<b>Findings</b>", styles["RJCellH"])]]
    for cat, n in cov.items():
        rows.append([Paragraph(_esc(cat), styles["RJCell"]),
                     Paragraph(str(n), styles["RJCell"])])
    if len(rows) == 1:
        rows.append([Paragraph("No categorised findings", styles["RJCell"]),
                     Paragraph("0", styles["RJCell"])])
    t = Table(rows, colWidths=[None, 24 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    flow.append(t)
    return flow


def _appendix(r, styles):
    flow = [PageBreak(), Paragraph("7. Appendices", styles["RJH1"])]
    tools = r.get("meta", {}).get("external_tools", {})
    used = [n for n, ok in tools.items() if ok]
    flow.append(Paragraph("7.1 Tools & Environment", styles["RJH2"]))
    flow.append(Paragraph(
        "Built-in checks (always run): HTTP security headers, cookies, TLS/SSL, "
        "information exposure, DNS & email security, CORS, content/technology "
        "analysis, TCP port scan, WAF detection.", styles["RJBody"]))
    flow.append(Paragraph("External open-source tools active on the host: "
                          + (", ".join(used) if used else "none detected"),
                          styles["RJBody"]))
    flow.append(Paragraph("7.2 Assessment Log", styles["RJH2"]))
    for line in r.get("tool_log", []):
        flow.append(Paragraph(_esc(line), styles["RJSmall"]))
    if r.get("errors"):
        flow.append(Paragraph("7.3 Notes / Errors", styles["RJH2"]))
        for line in r["errors"]:
            flow.append(Paragraph(_esc(line), styles["RJSmall"]))
    flow.append(Spacer(1, 6 * mm))
    flow.append(HRFlowable(width="100%", thickness=0.6, color=ACCENT))
    flow.append(Paragraph(f"<b>{_esc(config.AUTHOR_MARK)}</b>", ParagraphStyle(
        "end", alignment=TA_CENTER, textColor=PRIMARY, fontSize=10)))
    flow.append(Paragraph(f"— End of Report · {config.BRAND_NAME} —",
                          ParagraphStyle("e2", alignment=TA_CENTER,
                                         textColor=colors.grey, fontSize=8)))
    return flow


def _grid_style():
    return TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PRIMARY),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ])


def _auto_ref() -> str:
    return f"{config.REPORT_DOC_PREFIX}-{datetime.now().strftime('%Y%m%d-%H%M')}"
