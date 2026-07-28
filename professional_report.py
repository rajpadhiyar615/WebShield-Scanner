from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from datetime import datetime


def generate_professional_report(filename, data):

    doc = SimpleDocTemplate(filename, pagesize=letter)

    styles = getSampleStyleSheet()

    content = []

    # ==========================
    # TITLE
    # ==========================

    content.append(
        Paragraph(
            "WebShield Security Assessment Report",
            styles["Title"],
        )
    )

    content.append(Spacer(1, 20))

    # ==========================
    # SCAN INFORMATION
    # ==========================

    url = data.get("URL", "N/A")

    scan_info = f"""
    <b>Target Website:</b> {url}<br/>
    <b>Scan Date:</b> {datetime.now().strftime("%d-%m-%Y %H:%M")}
    """

    content.append(Paragraph(scan_info, styles["Normal"]))

    content.append(Spacer(1, 20))

    # ==========================
    # SECURITY SCORE
    # ==========================

    content.append(Paragraph("Security Score", styles["Heading2"]))

    security = data.get("Security Score", {})

    score = security.get("Score", 0)
    severity = security.get("Severity", "Unknown")

    score_table = Table(
        [
            ["Score", "Risk Level"],
            [str(score), severity],
        ]
    )

    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ]
        )
    )

    content.append(score_table)

    content.append(Spacer(1, 20))

    # ==========================
    # EXECUTIVE SUMMARY
    # ==========================

    vulnerabilities = data.get("Vulnerabilities", [])

    # Remove duplicate vulnerabilities
    unique = []
    seen = set()

    for vuln in vulnerabilities:

        name = vuln.get("name", vuln.get("Name", "Unknown"))

        if name not in seen:
            seen.add(name)
            unique.append(vuln)

    vulnerabilities = unique

    high = 0
    medium = 0
    low = 0
    unknown = 0

    for vuln in vulnerabilities:

        sev = (vuln.get("severity", "") or vuln.get("Severity", "")).lower()

        if sev == "high":
            high += 1

        elif sev == "medium":
            medium += 1

        elif sev == "low":
            low += 1

        else:
            unknown += 1

    content.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"],
        )
    )

    summary = f"""
    <b>Total Vulnerabilities:</b> {len(vulnerabilities)}<br/>
    <b>High:</b> {high}<br/>
    <b>Medium:</b> {medium}<br/>
    <b>Low:</b> {low}<br/>
    <b>Unknown:</b> {unknown}
    """

    content.append(Paragraph(summary, styles["Normal"]))

    content.append(Spacer(1, 20))

    # ==========================
    # VULNERABILITY FINDINGS
    # ==========================

    content.append(
        Paragraph(
            "Vulnerability Findings",
            styles["Heading2"],
        )
    )

    table_data = [["Name", "OWASP", "CVSS", "Severity"]]

    for vuln in vulnerabilities:

        cvss = vuln.get("cvss", vuln.get("CVSS", "N/A"))

        if isinstance(cvss, dict):
            cvss = cvss.get("score", "N/A")

        table_data.append(
            [
                vuln.get("name", vuln.get("Name", "Unknown")),
                vuln.get("owasp", vuln.get("OWASP", "Unknown")),
                str(cvss),
                vuln.get("severity", vuln.get("Severity", "Unknown")),
            ]
        )

    table = Table(table_data)

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ]
        )
    )

    content.append(table)

    content.append(Spacer(1, 20))

    # ==========================
    # RECOMMENDATIONS
    # ==========================

    content.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading2"],
        )
    )

    if vulnerabilities:

        for vuln in vulnerabilities:

            recommendation = vuln.get("recommendation", {})

            if isinstance(recommendation, dict):

                issue = recommendation.get("issue", "Security Issue")

                impact = recommendation.get("impact", "No impact available.")

                fixes = recommendation.get("fix", [])

                text = f"<b>{issue}</b><br/>"
                text += f"<b>Impact:</b> {impact}<br/><br/>"

                if fixes:

                    text += "<b>Recommended Fixes:</b><br/>"

                    for fix in fixes:
                        text += f"• {fix}<br/>"

            else:

                text = str(recommendation)

            content.append(
                Paragraph(
                    text,
                    styles["Normal"],
                )
            )

            content.append(Spacer(1, 10))

    else:

        content.append(
            Paragraph(
                "No vulnerabilities detected.",
                styles["Normal"],
            )
        )

    # ==========================
    # FOOTER
    # ==========================

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "<b>Generated by WebShield Scanner</b><br/>"
            "Developer: Raj Padhiyar<br/>"
            "Version: 1.0",
            styles["Normal"],
        )
    )

    # ==========================
    # BUILD PDF
    # ==========================

    doc.build(content)

    with open(filename, "rb") as file:
        return file.read()
