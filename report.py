from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.colors import navy


def generate_report(filename, data):

    doc = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    title = styles["Title"]
    title.alignment = TA_CENTER
    title.textColor = navy

    heading = styles["Heading2"]
    normal = styles["Normal"]

    story = []

    story.append(
        Paragraph("WebShield Scanner Report", title)
    )

    story.append(Spacer(1, 20))

    for section, content in data.items():

        story.append(
            Paragraph(section, heading)
        )

        story.append(Spacer(1, 8))

        if isinstance(content, dict):

            for key, value in content.items():

                story.append(
                    Paragraph(
                        f"<b>{key}</b>: {value}",
                        normal
                    )
                )

        elif isinstance(content, list):

            for item in content:

                story.append(
                    Paragraph(str(item), normal)
                )

        else:

            story.append(
                Paragraph(str(content), normal)
            )

        story.append(Spacer(1, 15))

    doc.build(story)