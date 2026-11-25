from docx import Document


def analyze_docx(file_path: str) -> dict:

    findings = []

    try:
        document = Document(file_path)

        # Check external relationships
        for relationship in document.part.rels.values():

            if relationship.is_external:
                findings.append(
                    {
                        "title": "External Relationship Detected",
                        "description": (
                            "The DOCX document references an external resource."
                        ),
                        "severity": "medium",
                    }
                )

        # Extract document text
        extracted_text = "\n".join(paragraph.text for paragraph in document.paragraphs)

        suspicious_keywords = [
            "steal password",
            "send your password",
            "verify your bank account",
            "download malware",
            "disable antivirus",
        ]

        text_lower = extracted_text.lower()

        for keyword in suspicious_keywords:

            if keyword in text_lower:
                findings.append(
                    {
                        "title": "Suspicious Text Detected",
                        "description": (
                            f"The document contains potentially suspicious "
                            f"text: '{keyword}'."
                        ),
                        "severity": "medium",
                    }
                )

        return {
            "file_type": "DOCX",
            "paragraph_count": len(document.paragraphs),
            "text_length": len(extracted_text),
            "findings": findings,
            "status": "analyzed",
        }

    except Exception as error:
        raise ValueError("Unable to analyze this DOCX file.") from error
