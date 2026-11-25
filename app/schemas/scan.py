
from typing import Literal

from pydantic import BaseModel, HttpUrl, Field


class URLScanRequest(BaseModel):
    url: HttpUrl


class ScanResponse(BaseModel):
    scan_id: str
    status: Literal["completed", "processing", "failed"]
    risk_level: Literal[
        "low_risk",
        "suspicious",
        "high_risk",
        "confirmed_malicious",
        "inconclusive"
    ]
    target: str
    message: str


class ScanHistoryItem(BaseModel):
    scan_id: str
    target: str
    scan_type: Literal["url", "file"]
    risk_level: Literal[
        "low_risk",
        "suspicious",
        "high_risk",
        "confirmed_malicious",
        "inconclusive"
    ]
    scanned_at: str
