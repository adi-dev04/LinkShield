from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers.auth import require_login
from app.models import Scan, Finding

router = APIRouter(prefix="/api/scan", tags=["Scan Details"])


@router.get("/{scan_id}")
async def get_scan_details(
    scan_id: str, db: Session = Depends(get_db), user=Depends(require_login)
):
    scan = (
        db.query(Scan).filter(Scan.scan_id == scan_id, Scan.user_id == user.id).first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return {
        "scan_id": scan.scan_id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "risk_level": scan.risk_level,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
            }
            for finding in findings
        ],
    }
