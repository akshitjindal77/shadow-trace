"""
ShadowTrace API Schemas

Pydantic models for request/response validation.
"""
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime


class ScanCreateRequest(BaseModel):
    """Request model for initiating a scan."""

    input_value: str = Field(..., min_length=1, max_length=255)
    input_type: Literal["email", "username", "domain"]
    consent: bool


class ScanCreateResponse(BaseModel):
    """Response model after creating a scan."""

    scan_id: str
    overall_risk_score: float = Field(..., ge=0, le=100)


class ScanHistoryResponse(BaseModel):
    """Response model for scan history entries."""

    scan_id: str
    input_value: str
    input_type: str
    overall_risk_score: float
    risk_level: str
    scan_timestamp: datetime

    class Config:
        from_attributes = True


class ScanDetailResponse(BaseModel):
    """Response model for detailed scan results."""

    scan_id: str
    input_value: str
    input_type: str
    scan_timestamp: datetime
    overall_risk_score: float
    risk_level: str
    breach_count: int
    platforms_found: int
    dork_results_count: int
    findings: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    pdf_report_path: Optional[str] = None
    scan_duration_seconds: float


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str = "1.0.0"
