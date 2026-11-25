
import fitz


def analyze_pdf(file_path: str) -> dict:

    findings = []
    document = None

    try:
        document = fitz.open(file_path)

        if document.is_encrypted:
            findings.append({
                "title": "Encrypted PDF Detected",
                "description": "The PDF is encrypted and its contents may require a password.",
                "severity": "medium"
            })

        page_count = len(document)

        if page_count == 0:
            findings.append({
                "title": "Empty PDF",
                "description": "The PDF contains no pages.",
                "severity": "low"
            })

        extracted_text = ""

        for page in document:
            extracted_text += page.get_text()

        suspicious_keywords = [
            "steal password",
            "send your password",
            "verify your bank account",
            "download malware",
            "disable antivirus"
        ]

        text_lower = extracted_text.lower()

        for keyword in suspicious_keywords:
            if keyword in text_lower:
                findings.append({
                    "title": "Suspicious Text Detected",
                    "description": f"The PDF contains potentially suspicious text: '{keyword}'.",
                    "severity": "medium"
                })

        metadata = document.metadata or {}

        if not metadata.get("title"):
            findings.append({
                "title": "Missing PDF Title",
                "description": "The PDF does not contain title metadata.",
                "severity": "low"
            })

        return {
            "file_type": "PDF",
            "page_count": page_count,
            "text_length": len(extracted_text),
            "findings": findings,
            "status": "analyzed"
        }

    except Exception as error:
        raise ValueError("Unable to analyze this PDF file.") from error

    finally:
        if document is not None:
            document.close()
