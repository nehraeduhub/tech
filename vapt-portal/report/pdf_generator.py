"""Tech Guardians branded PDF report generator (pure reportlab, portable)."""
from __future__ import annotations

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)

# --- Tech Guardians brand palette ---
BRAND_PRIMARY = colors.HexColor("#0b3c82")
BRAND_ACCENT = colors.HexColor("#1e6fd9")
BRAND_LIGHT = colors.HexColor("#eaf2ff")
INK = colors.HexColor("#1b2430")

SEV_COLORS = {
    "critical": colors.HexColor("#b00020"),
    "high": colors.HexColor("#e2571e"),
    "medium": colors.HexColor("#e0a800"),
    "low": colors.HexColor("#2a9d8f"),
    "info": colors.HexColor("#5a6470"),
}

BRAND_NAME = "Tech Guardians"
BRAND_TAGLINE = "Vulnerability Assessment & Penetration Testing"


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("TGTitle", parent=ss["Title"], textColor=BRAND_PRIMARY,
                          fontSize=26, leading=30))
    ss.add(ParagraphStyle("TGH1", parent=ss["Heading1"], textColor=BRAND_PRIMARY,
                          fontSize=15, spaceBefore=12, spaceAfter=6))
    ss.add(ParagraphStyle("TGH2", parent=ss["Heading2"], textColor=BRAND_ACCENT,
                          fontSize=12, spaceBefore=8, spaceAfter=4))
    ss.add(ParagraphStyle("TGBody", parent=ss["BodyText"], textColor=INK,
                          fontSize=9.5, leading=14))
    ss.add(ParagraphStyle("TGSmall", parent=ss["BodyText"], textColor=colors.grey,
                          fontSize=8, leading=11))
    ss.add(ParagraphStyle("TGCenter", parent=ss["BodyText"], alignment=TA_CENTER,
                          textColor=colors.white, fontSize=10))
    return ss


def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    # Header band
    canvas.setFillColor(BRAND_PRIMARY)
    canvas.rect(0, h - 18 * mm, w, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(16 * mm, h - 12 * mm, BRAND_NAME)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 16 * mm, h - 12 * mm, "CONFIDENTIAL — VAPT REPORT")
    # Footer
    canvas.setStrokeColor(BRAND_ACCENT)
    canvas.setLineWidth(0.5)
    canvas.line(16 * mm, 14 * mm, w - 16 * mm, 14 * mm)
    canvas.setFillColor(colors.grey)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(16 * mm, 10 * mm,
                      f"{BRAND_NAME} · {BRAND_TAGLINE}")
    canvas.drawRightString(w - 16 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _severity_chip(sev: str, styles):
    color = SEV_COLORS.get(sev, colors.grey)
    t = Table([[Paragraph(f"<b>{sev.upper()}</b>",
                          ParagraphStyle("c", textColor=colors.white,
                                         fontSize=8, alignment=TA_CENTER))]],
              colWidths=[24 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build_report(result_dict: dict, output_path: str,
                 client_name: str = "", assessor: str = "",
                 engagement_ref: str = "") -> str:
    """Render the scan result dict to a branded PDF. Returns the path."""
    styles = _styles()
    doc = BaseDocTemplate(
        output_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=24 * mm, bottomMargin=18 * mm,
        title=f"{BRAND_NAME} VAPT Report",
        author=BRAND_NAME,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="tg", frames=[frame],
                                       onPage=_header_footer)])

    story = []
    story += _cover(result_dict, styles, client_name, assessor, engagement_ref)
    story.append(PageBreak())
    story += _summary(result_dict, styles)
    story += _attack_surface(result_dict, styles)
    story.append(PageBreak())
    story += _findings(result_dict, styles)
    story += _methodology(result_dict, styles)

    doc.build(story)
    return output_path


def _cover(r, styles, client_name, assessor, ref):
    logo_svg = os.path.join(os.path.dirname(__file__), "assets", "logo.svg")
    flow = [Spacer(1, 30 * mm)]
    # Draw logo if the SVG renderer is available; otherwise skip gracefully.
    try:
        from svglib.svglib import svg2rlg  # type: ignore
        drawing = svg2rlg(logo_svg)
        if drawing:
            scale = (40 * mm) / drawing.height
            drawing.scale(scale, scale)
            drawing.width *= scale
            drawing.height *= scale
            drawing.hAlign = "CENTER"
            flow.append(drawing)
    except Exception:  # noqa: BLE001 - svglib optional
        pass

    flow += [
        Spacer(1, 10 * mm),
        Paragraph(BRAND_NAME, styles["TGTitle"]),
        Paragraph(BRAND_TAGLINE, ParagraphStyle(
            "sub", alignment=TA_CENTER, textColor=BRAND_ACCENT, fontSize=12)),
        Spacer(1, 4 * mm),
        HRFlowable(width="60%", thickness=1.2, color=BRAND_ACCENT),
        Spacer(1, 16 * mm),
        Paragraph("Security Assessment Report", ParagraphStyle(
            "rt", alignment=TA_CENTER, textColor=INK, fontSize=16)),
        Spacer(1, 10 * mm),
    ]

    meta = [
        ["Target", r.get("normalized_url", r.get("target", "—"))],
        ["Client", client_name or "—"],
        ["Assessor", assessor or BRAND_NAME],
        ["Engagement Ref.", ref or "—"],
        ["Report Date", datetime.now().strftime("%d %B %Y")],
        ["Overall Risk", f"{r.get('risk_rating','—')} "
                         f"(score {r.get('risk_score','—')}/100)"],
    ]
    t = Table(meta, colWidths=[40 * mm, None])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), BRAND_LIGHT),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_PRIMARY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    flow.append(t)
    flow += [
        Spacer(1, 14 * mm),
        Paragraph(
            "This document contains confidential security information intended "
            "solely for the named client. It describes weaknesses identified "
            "during an <b>authorised</b> assessment. Handle and distribute on a "
            "strict need-to-know basis.", styles["TGSmall"]),
    ]
    return flow


def _summary(r, styles):
    counts = r.get("severity_counts", {})
    flow = [Paragraph("1. Executive Summary", styles["TGH1"])]
    flow.append(Paragraph(
        f"An automated vulnerability assessment was performed against "
        f"<b>{r.get('normalized_url','the target')}</b>. The assessment produced "
        f"an overall risk rating of <b>{r.get('risk_rating','—')}</b> "
        f"(score {r.get('risk_score','—')}/100), based on "
        f"{sum(counts.values())} finding(s).", styles["TGBody"]))
    flow.append(Spacer(1, 4 * mm))

    header = ["Critical", "High", "Medium", "Low", "Info"]
    row = [str(counts.get(k, 0)) for k in
           ("critical", "high", "medium", "low", "info")]
    t = Table([header, row], colWidths=[None] * 5)
    style = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
    ]
    for i, sev in enumerate(("critical", "high", "medium", "low", "info")):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLORS[sev]))
        style.append(("BACKGROUND", (i, 1), (i, 1), BRAND_LIGHT))
    t.setStyle(TableStyle(style))
    flow.append(t)
    flow.append(Spacer(1, 6 * mm))
    return flow


def _attack_surface(r, styles):
    """Aggregate attack classes the findings could enable (risk context)."""
    surface: dict[str, int] = {}
    for f in r.get("findings", []):
        for a in f.get("attack_surface", []):
            surface[a] = surface.get(a, 0) + 1
    flow = [Paragraph("2. Potential Attack Surface", styles["TGH1"])]
    flow.append(Paragraph(
        "The weaknesses identified could, if left unresolved, expose the target "
        "to the following classes of attack. This is provided for risk "
        "prioritisation; it is not exploitation guidance.", styles["TGBody"]))
    flow.append(Spacer(1, 3 * mm))
    if surface:
        rows = [["Attack Class", "Related Findings"]]
        for name, n in sorted(surface.items(), key=lambda x: -x[1]):
            rows.append([name, str(n)])
        t = Table(rows, colWidths=[None, 35 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        flow.append(t)
    else:
        flow.append(Paragraph("No notable attack surface identified.",
                              styles["TGBody"]))
    return flow


def _findings(r, styles):
    flow = [Paragraph("3. Detailed Findings", styles["TGH1"])]
    findings = r.get("findings", [])
    if not findings:
        flow.append(Paragraph("No findings were produced by the automated checks. "
                              "A manual review is still recommended.",
                              styles["TGBody"]))
        return flow

    for i, f in enumerate(findings, 1):
        flow.append(Spacer(1, 3 * mm))
        head = Table(
            [[Paragraph(f"<b>{i}. {_esc(f['title'])}</b>", styles["TGH2"]),
              _severity_chip(f.get("severity", "info"), styles)]],
            colWidths=[None, 26 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        flow.append(head)

        detail = [
            ["Category", f.get("category", "—")],
            ["Description", _esc(f.get("description", ""))],
        ]
        if f.get("evidence"):
            detail.append(["Evidence", _esc(f["evidence"])])
        if f.get("attack_surface"):
            detail.append(["Could enable", ", ".join(f["attack_surface"])])
        if f.get("recommendation"):
            detail.append(["Remediation", _esc(f["recommendation"])])
        if f.get("references"):
            detail.append(["References", "<br/>".join(f["references"])])

        rows = [[Paragraph(f"<b>{k}</b>", styles["TGBody"]),
                 Paragraph(v, styles["TGBody"])] for k, v in detail]
        t = Table(rows, colWidths=[28 * mm, None])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), BRAND_LIGHT),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        flow.append(t)
    return flow


def _methodology(r, styles):
    flow = [PageBreak(), Paragraph("4. Methodology & Scope", styles["TGH1"])]
    tools = r.get("meta", {}).get("external_tools", {})
    used = [name for name, ok in tools.items() if ok] or ["built-in checks only"]
    flow.append(Paragraph(
        "The assessment combined passive inspection and non-intrusive automated "
        "checks. No exploitation, brute-forcing or denial-of-service techniques "
        "were used. Checks included HTTP security headers, cookie attributes, "
        "TLS/SSL configuration, information exposure, DNS posture and, where "
        "available, industry-standard open-source scanners.", styles["TGBody"]))
    flow.append(Spacer(1, 3 * mm))
    flow.append(Paragraph(f"<b>Scanners active on host:</b> {', '.join(used)}",
                          styles["TGBody"]))
    flow.append(Spacer(1, 3 * mm))
    flow.append(Paragraph(
        "<b>Authorisation:</b> This assessment was conducted only after the "
        "operator confirmed written authorisation to test the target system.",
        styles["TGBody"]))
    flow.append(Spacer(1, 6 * mm))
    flow.append(Paragraph("Assessment Log", styles["TGH2"]))
    for line in r.get("tool_log", []):
        flow.append(Paragraph(_esc(line), styles["TGSmall"]))
    if r.get("errors"):
        flow.append(Spacer(1, 3 * mm))
        flow.append(Paragraph("Notes / Errors", styles["TGH2"]))
        for line in r["errors"]:
            flow.append(Paragraph(_esc(line), styles["TGSmall"]))
    return flow


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
