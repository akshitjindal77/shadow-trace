"""
ShadowTrace API Schemas

Pydantic models for request/response validation.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime


class ScanRequest(BaseModel):
    """Request model for initiating a scan."""
    
    query: str = Field(..., min_length=1, max_length=255, description="Email, username, or domain to scan")


class AnalysisResult(BaseModel):
    """Individual analyzer result."""
    
    analyzer: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: float


class ScanResponse(BaseModel):
    """Response model for completed scan."""
    
    query_input: str
    query_type: str
    risk_score: float = Field(..., ge=0, le=100, description="Risk score from 0-100")
    risk_level: str = Field(..., description="critical, high, medium, low, or minimal")
    
    breaches_found: int
    platforms_found: int
    email_reputation_score: Optional[float] = None
    
    domain_info: Optional[Dict[str, Any]] = None
    social_footprint: Optional[Dict[str, Any]] = None
    dork_results: Optional[Dict[str, Any]] = None
    
    recommendations: List[str]
    
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    """Response model for scan history."""
    
    id: int
    query_input: str
    query_type: str
    risk_score: float
    risk_level: str
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    """Detailed scan response with all data."""
    
    id: int
    full_results: Optional[Dict[str, Any]] = None


class ReportRequest(BaseModel):
    """Request model for generating PDF report."""
    
    scan_id: int = Field(..., description="ID of the scan result")
    format: str = Field("pdf", description="Report format: pdf or json")


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str
    version: str = "1.0.0"
