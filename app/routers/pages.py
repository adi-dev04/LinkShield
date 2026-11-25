from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.core.config import TEMPLATES_DIR
from app.database import get_db
from app.routers.auth import require_login
from app.models import Scan, Finding
from datetime import timezone, timedelta
from app.services.risk_analyzer import calculate_risk_score

router = APIRouter()

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def convert_to_ist(dt):
    if dt is None:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    ist = timezone(timedelta(hours=5, minutes=30))

    return dt.astimezone(ist).strftime("%d %b %Y, %I:%M:%S %p")


@router.get("/")
async def dashboard(
    request: Request, db: Session = Depends(get_db), user=Depends(require_login)
):
    records = (
        db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "total_scans": len(records),
            "low_risk": sum(1 for s in records if s.risk_level == "low_risk"),
            "suspicious": sum(1 for s in records if s.risk_level == "suspicious"),
            "high_risk": sum(
                1
                for s in records
                if s.risk_level in ["high_risk", "confirmed_malicious"]
            ),
            "recent_scans": [
                {"scan": scan, "display_date": convert_to_ist(scan.created_at)}
                for scan in records[:5]
            ],
        },
    )


@router.get("/url-scanner")
async def url_scanner(request: Request, user=Depends(require_login)):
    return templates.TemplateResponse(
        request=request, name="url_scanner.html", context={}
    )


@router.get("/file-scanner")
async def file_scanner(request: Request, user=Depends(require_login)):
    return templates.TemplateResponse(
        request=request, name="file_scanner.html", context={}
    )


@router.get("/history")
async def history(
    request: Request, db: Session = Depends(get_db), user=Depends(require_login)
):
    records = (
        db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
    )
    for scan in records:
        scan.display_date = convert_to_ist(scan.created_at)

    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context={
            "scans": records,
            "total_scans": len(records),
            "url_scans": sum(1 for s in records if s.scan_type == "url"),
            "file_scans": sum(1 for s in records if s.scan_type == "file"),
            "high_risk_scans": sum(
                1
                for s in records
                if s.risk_level in ["high_risk", "confirmed_malicious"]
            ),
        },
    )


@router.get("/results/latest")
async def latest_results(
    request: Request, db: Session = Depends(get_db), user=Depends(require_login)
):
    scan = (
        db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="No scan records available.")

    return await results(request=request, scan_id=scan.scan_id, db=db)


@router.get("/results/{scan_id}")
async def results(
    request: Request,
    scan_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_login),
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

    return templates.TemplateResponse(
        request=request,
        name="results.html",
        context={
            "scan": scan,
            "findings": findings_data,
            "risk_level": scan.risk_level,
            "risk_score": risk_result["risk_score"],
            "display_date": convert_to_ist(scan.created_at),
        },
    )


@router.get("/report/{scan_id}")
async def report(
    request: Request,
    scan_id: str,
    db: Session = Depends(get_db),
    user=Depends(require_login),
):
    scan = (
        db.query(Scan).filter(Scan.scan_id == scan_id, Scan.user_id == user.id).first()
    )

    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    return templates.TemplateResponse(
        request=request, name="report.html", context={"scan_id": scan_id}
    )
