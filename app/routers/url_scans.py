import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.routers.auth import require_login
from app.database import get_db
from app.models import Scan, Finding
from app.services.risk_analyzer import calculate_risk_score
from app.schemas.scan import URLScanRequest, ScanResponse
from app.services.url_scanner import analyze_url

router = APIRouter(prefix="/api/scan", tags=["URL Scanning"])


@router.post("/url", response_model=ScanResponse)
async def scan_url(
    scan_data: URLScanRequest,
    db: Session = Depends(get_db),
    user=Depends(require_login),
):

    try:
        result = analyze_url(str(scan_data.url))
        risk_result = calculate_risk_score(result["findings"])
        scan_id = str(uuid.uuid4())

        scan = Scan(
            user_id=user.id,
            scan_id=scan_id,
            scan_type="url",
            target=result["normalized_url"],
            status="completed",
            risk_level=risk_result["risk_level"],
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

        return ScanResponse(
            scan_id=scan_id,
            status="completed",
            risk_level=risk_result["risk_level"],
            target=result["normalized_url"],
            message="URL analysis completed successfully.",
        )

    except ValueError as error:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(error))

    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while scanning the URL.",
        ) from error
