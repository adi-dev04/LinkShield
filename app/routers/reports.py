from io import BytesIO
from datetime import timezone, timedelta
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.routers.auth import require_login

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)

from app.database import get_db
from app.models import Scan, Finding
from app.services.risk_analyzer import calculate_risk_score

router = APIRouter(prefix="/api/report", tags=["Reports"])


# --------------------------------------------------
# REPORT DESIGN
# --------------------------------------------------

NAVY = colors.HexColor("#172B4D")
DARK = colors.HexColor("#263445")
BLUE = colors.HexColor("#315B85")
LIGHT_GREY = colors.HexColor("#F2F4F7")
BORDER = colors.HexColor("#D6DCE5")
GREY = colors.HexColor("#687586")


def convert_to_ist(dt):

    if dt is None:
        return "Not available"

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    ist = timezone(timedelta(hours=5, minutes=30))

    return dt.astimezone(ist).strftime("%d %b %Y, %I:%M:%S %p")


def safe_text(value):
    return escape(str(value)) if value is not None else "Not available"


def draw_page_header_footer(canvas, document):

    canvas.saveState()

    page_width, page_height = A4

    # Header
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.6)
    canvas.line(
        20 * mm, page_height - 18 * mm, page_width - 20 * mm, page_height - 18 * mm
    )

    canvas.setFont("Helvetica-Bold", 9)
    canvas.setFillColor(NAVY)
    canvas.drawString(20 * mm, page_height - 14 * mm, "LINKSHIELD")

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawRightString(
        page_width - 20 * mm, page_height - 14 * mm, "SECURITY INVESTIGATION REPORT"
    )

    # Footer
    canvas.setStrokeColor(BORDER)
    canvas.line(20 * mm, 15 * mm, page_width - 20 * mm, 15 * mm)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(20 * mm, 10 * mm, "LinkShield | Confidential Report")
    canvas.drawRightString(page_width - 20 * mm, 10 * mm, f"Page {document.page}")

    canvas.restoreState()


# --------------------------------------------------
# PDF REPORT ENDPOINT
# --------------------------------------------------


@router.get("/{scan_id}/pdf")
async def download_report(
    scan_id: str, db: Session = Depends(get_db), user=Depends(require_login)
):

    scan = (
        db.query(Scan).filter(Scan.scan_id == scan_id, Scan.user_id == user.id).first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    findings_data = [
        {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
        }
        for finding in findings
    ]

    risk_result = calculate_risk_score(findings_data)

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=28 * mm,
        bottomMargin=23 * mm,
        title="LinkShield Security Investigation Report",
        author="LinkShield",
    )

    styles = getSampleStyleSheet()

    report_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        textColor=NAVY,
        alignment=TA_LEFT,
        spaceAfter=6,
    )

    subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=15,
        textColor=GREY,
        spaceAfter=16,
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=NAVY,
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=DARK,
        spaceAfter=6,
    )

    label_style = ParagraphStyle(
        "TableLabel",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
    )

    value_style = ParagraphStyle(
        "TableValue",
        parent=body_style,
        fontSize=8,
        leading=11,
        wordWrap="CJK",
    )

    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=NAVY,
        spaceAfter=5,
    )

    story = []

    # --------------------------------------------------
    # REPORT COVER HEADING
    # --------------------------------------------------

    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Security Investigation Report", report_title))

    story.append(
        Paragraph("Technical assessment and documented security observations", subtitle)
    )

    story.append(
        Paragraph(
            "<b>REPORT CLASSIFICATION:</b> INTERNAL SECURITY ASSESSMENT", body_style
        )
    )

    story.append(Spacer(1, 8))

    # --------------------------------------------------
    # 1. INVESTIGATION DETAILS
    # --------------------------------------------------

    story.append(Paragraph("1. Investigation Details", section_heading))

    overview_data = [
        [
            Paragraph("REFERENCE ID", label_style),
            Paragraph(safe_text(scan.scan_id), value_style),
        ],
        [
            Paragraph("ASSESSMENT TYPE", label_style),
            Paragraph(safe_text(scan.scan_type.upper()), value_style),
        ],
        [
            Paragraph("TARGET", label_style),
            Paragraph(safe_text(scan.target), value_style),
        ],
        [
            Paragraph("ASSESSMENT DATE", label_style),
            Paragraph(safe_text(convert_to_ist(scan.created_at)), value_style),
        ],
        [
            Paragraph("PROCESSING STATUS", label_style),
            Paragraph(safe_text(scan.status.title()), value_style),
        ],
    ]

    overview_table = Table(
        overview_data,
        colWidths=[43 * mm, 127 * mm],
        repeatRows=0,
    )

    overview_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
                ("BACKGROUND", (1, 0), (1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    story.append(overview_table)

    # --------------------------------------------------
    # 2. ASSESSMENT SUMMARY
    # --------------------------------------------------

    story.append(Paragraph("2. Assessment Summary", section_heading))

    risk_score = risk_result.get("risk_score")
    risk_level = risk_result.get("risk_level", "inconclusive")

    score_text = f"{risk_score}/100" if risk_score is not None else "Not calculated"

    risk_display = risk_level.replace("_", " ").title()

    risk_data = [
        [
            Paragraph("RISK CLASSIFICATION", label_style),
            Paragraph("RISK SCORE", label_style),
        ],
        [
            Paragraph(safe_text(risk_display), value_style),
            Paragraph(safe_text(score_text), value_style),
        ],
    ]

    risk_table = Table(
        risk_data,
        colWidths=[85 * mm, 85 * mm],
    )

    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), LIGHT_GREY),
                ("BACKGROUND", (0, 1), (-1, 1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )

    story.append(risk_table)

    # --------------------------------------------------
    # 3. SECURITY FINDINGS
    # --------------------------------------------------

    story.append(
        Paragraph(f"3. Security Findings ({len(findings)} recorded)", section_heading)
    )

    if findings:

        for index, finding in enumerate(findings, start=1):

            finding_content = [
                Paragraph(f"{index}. {safe_text(finding.title)}", finding_title_style),
                Paragraph(safe_text(finding.description), body_style),
                Paragraph(
                    f"<b>Severity:</b> {safe_text(finding.severity.upper())}",
                    body_style,
                ),
                Spacer(1, 7),
            ]

            story.append(KeepTogether(finding_content))

    else:

        story.append(
            Paragraph(
                "No configured warning indicators were detected "
                "during this assessment.",
                body_style,
            )
        )

    # --------------------------------------------------
    # 4. CONCLUSION
    # --------------------------------------------------

    story.append(Paragraph("4. Assessment Conclusion", section_heading))

    if findings:

        conclusion = (
            f"The assessment recorded {len(findings)} security "
            "finding(s). The observations listed in this report "
            "should be reviewed in accordance with their severity "
            "and the context of the assessed target."
        )

    else:

        conclusion = (
            "The configured analysis checks did not identify any "
            "warning indicators. This result is limited to the "
            "checks performed and should not be interpreted as "
            "confirmation that the target is completely safe."
        )

    story.append(Paragraph(conclusion, body_style))

    # --------------------------------------------------
    # 5. SCOPE AND LIMITATIONS
    # --------------------------------------------------

    story.append(Paragraph("5. Scope and Limitations", section_heading))

    story.append(
        Paragraph(
            "This report documents the results produced by "
            "LinkShield's configured analysis procedures. Findings "
            "represent observed indicators and do not independently "
            "establish malicious intent. The assessment may not "
            "identify every possible security threat.",
            body_style,
        )
    )

    story.append(
        Paragraph(
            "A low-risk classification does not guarantee that a "
            "URL or file is safe. Additional investigation using "
            "appropriate security tools may be required.",
            body_style,
        )
    )

    story.append(Spacer(1, 12))

    story.append(
        Paragraph(
            "<b>END OF REPORT</b>",
            ParagraphStyle(
                "EndReport",
                parent=body_style,
                alignment=TA_CENTER,
                textColor=GREY,
                fontSize=8,
                spaceBefore=8,
            ),
        )
    )

    document.build(
        story,
        onFirstPage=draw_page_header_footer,
        onLaterPages=draw_page_header_footer,
    )

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="LinkShield_Report_{scan_id}.pdf"'
            )
        },
    )
