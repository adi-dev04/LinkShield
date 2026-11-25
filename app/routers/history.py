from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.routers.auth import require_login
from app.models import Scan
from app.schemas.scan import ScanHistoryItem

router = APIRouter(prefix="/api", tags=["Scan History"])


@router.get("/history", response_model=list[ScanHistoryItem])
async def get_scan_history(db: Session = Depends(get_db), user=Depends(require_login)):
    records = (
        db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
    )
    return [
        ScanHistoryItem(
            scan_id=record.scan_id,
            target=record.target,
            scan_type=record.scan_type,
            risk_level=record.risk_level,
            scanned_at=record.created_at.isoformat(),
        )
        for record in records
    ]
