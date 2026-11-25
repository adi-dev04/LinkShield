import os
import tempfile
import uuid

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.apk_scanner import analyze_apk
from app.routers.auth import require_login
from app.models import Scan, Finding
from app.services.risk_analyzer import calculate_risk_score

from app.services.pdf_scanner import analyze_pdf
from app.services.docx_scanner import analyze_docx
from app.services.zip_scanner import analyze_zip
from app.services.exe_scanner import analyze_exe

router = APIRouter(prefix="/api/scan", tags=["File Scanning"])


@router.post("/file")
async def scan_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(require_login),
):

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    extension = os.path.splitext(file.filename)[1].lower()

    if extension not in [".pdf", ".docx", ".zip", ".exe", ".apk"]:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, DOCX, ZIP, EXE, and APK files are supported.",
        )

    temp_path = None

    try:
        MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
        content = await file.read(MAX_FILE_SIZE + 1)
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413, detail="File size exceeds the 10 MB upload limit."
            )
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        if extension == ".pdf" and not content.startswith(b"%PDF-"):
            raise HTTPException(status_code=400, detail="Invalid PDF file.")

        if extension == ".docx" and not content.startswith(b"PK"):
            raise HTTPException(status_code=400, detail="Invalid DOCX file.")
        if extension == ".zip" and not content.startswith(b"PK"):
            raise HTTPException(status_code=400, detail="Invalid ZIP file.")
        if extension == ".exe" and not content.startswith(b"MZ"):
            raise HTTPException(
                status_code=400, detail="Invalid Windows executable file."
            )
        if extension == ".apk" and not content.startswith(b"PK"):
            raise HTTPException(status_code=400, detail="Invalid APK file.")

        with tempfile.NamedTemporaryFile(delete=False, suffix=extension) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name

        if extension == ".pdf":
            result = analyze_pdf(temp_path)
        elif extension == ".docx":
            result = analyze_docx(temp_path)
        elif extension == ".zip":
            result = analyze_zip(temp_path)
        elif extension == ".exe":
            result = analyze_exe(temp_path)
        elif extension == ".apk":
            result = analyze_apk(temp_path)

        scan_id = str(uuid.uuid4())
        risk_result = calculate_risk_score(result["findings"])
        scan = Scan(
            user_id=user.id,
            scan_id=scan_id,
            scan_type="file",
            target=os.path.basename(file.filename),
            status="completed",
            risk_level=risk_result["risk_level"],
            file_name=os.path.basename(file.filename),
            file_size=len(content),
        )

        db.add(scan)

        for item in result["findings"]:
            finding = Finding(
                scan_id=scan_id,
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
            )

            db.add(finding)

        db.commit()

        response = {
            "scan_id": scan_id,
            "file_name": os.path.basename(file.filename),
            "file_size": len(content),
            "file_type": result["file_type"],
            "status": result["status"],
            "findings": result["findings"],
            "message": "File analysis completed successfully.",
        }

        if extension == ".pdf":
            response["page_count"] = result["page_count"]
            response["text_length"] = result["text_length"]
        elif extension == ".docx":
            response["paragraph_count"] = result["paragraph_count"]
            response["text_length"] = result["text_length"]
        elif extension == ".apk":
            response["file_count"] = result["file_count"]
            response["has_manifest"] = result["has_manifest"]
            response["has_dex"] = result["has_dex"]

        elif extension in [".zip"]:
            response["file_count"] = result["file_count"]
        else:
            response["executable_size"] = result["file_size"]

        return response

    except HTTPException:
        db.rollback()
        raise

    except ValueError as error:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(error))

    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while scanning the file.",
        ) from error

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

        await file.close()
