"""
ShadowTrace API Routes

Main API endpoints for scan operations and results.
"""
import asyncio
import json
import time
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.api.schemas import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanHistoryResponse,
    ScanDetailResponse,
    HealthResponse,
)
from backend.database.db import get_db
from backend.database.models import ScanResult
from backend.analyzers.breach_checker import check_breaches
from backend.analyzers.username_enumerator import enumerate_username
from backend.analyzers.email_reputation import check_email_reputation
from backend.analyzers.domain_intelligence import analyze_domain
from backend.analyzers.dork_scanner import run_dork_scan
from backend.analyzers.footprint_scorer import calculate_risk_score as calculate_footprint_score
from backend.utils.report_generator import generate_pdf_report, pdf_path_for_scan

router = APIRouter(prefix="/api", tags=["scanning"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="1.0.0")


@router.post("/scan", response_model=ScanCreateResponse)
async def initiate_scan(request: ScanCreateRequest, db: Session = Depends(get_db)):
    """Initiate a digital footprint scan and store the results."""
    if not request.consent:
        raise HTTPException(status_code=400, detail="User consent is required to perform a scan.")

    input_value = request.input_value.strip()
    if not input_value:
        raise HTTPException(status_code=400, detail="Input value must not be empty.")

    scan_id = str(uuid.uuid4())
    start_time = time.time()

    analyzer_results = await run_analyzers_for_type(input_value, request.input_type)
    scan_duration_seconds = time.time() - start_time

    footprint = calculate_footprint_score(analyzer_results)
    overall_risk_score = float(footprint.get("overall_score", 0))
    risk_level = footprint.get("risk_level", "LOW")
    recommendations = footprint.get("recommendations", [])

    breach_count = 0
    if analyzer_results.get("breaches", {}).get("success"):
        breach_count = analyzer_results["breaches"]["data"].get("breach_count", 0)

    platforms_found = 0
    if analyzer_results.get("username_enum", {}).get("success"):
        platforms_found = analyzer_results["username_enum"]["data"].get("platforms_found", 0)

    dork_results_count = 0
    if analyzer_results.get("dorks", {}).get("success"):
        for query_result in analyzer_results["dorks"]["data"].get("queries", []):
            dork_results_count += query_result.get("result_count", 0)

    scan_result = ScanResult(
        scan_id=scan_id,
        input_value=input_value,
        input_type=request.input_type,
        overall_risk_score=overall_risk_score,
        risk_level=risk_level,
        breach_count=breach_count,
        platforms_found=platforms_found,
        dork_results_count=dork_results_count,
        findings_json=json.dumps(analyzer_results, default=str),
        recommendations_json=json.dumps(recommendations, default=str),
        scan_duration_seconds=scan_duration_seconds,
    )

    db.add(scan_result)
    db.commit()
    db.refresh(scan_result)

    scan_result.pdf_report_path = str(pdf_path_for_scan(scan_id))
    db.commit()
    generate_pdf_report(scan_result)

    return ScanCreateResponse(
        scan_id=scan_id,
        overall_risk_score=overall_risk_score,
    )


@router.get("/history", response_model=List[ScanHistoryResponse])
async def get_scan_history(db: Session = Depends(get_db)):
    """Return the recent scan history."""
    scans = db.query(ScanResult).order_by(desc(ScanResult.scan_timestamp)).all()
    return scans


@router.get("/results/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    """Return detailed scan data for a scan_id."""
    scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        findings = json.loads(scan.findings_json)
    except Exception:
        findings = {}

    try:
        recommendations = json.loads(scan.recommendations_json)
    except Exception:
        recommendations = []

    return ScanDetailResponse(
        scan_id=scan.scan_id,
        input_value=scan.input_value,
        input_type=scan.input_type,
        scan_timestamp=scan.scan_timestamp,
        overall_risk_score=scan.overall_risk_score,
        risk_level=scan.risk_level,
        breach_count=scan.breach_count,
        platforms_found=scan.platforms_found,
        dork_results_count=scan.dork_results_count,
        findings=findings,
        recommendations=recommendations,
        pdf_report_path=scan.pdf_report_path,
        scan_duration_seconds=scan.scan_duration_seconds,
    )


@router.get("/export/{scan_id}")
async def export_scan_report(scan_id: str, db: Session = Depends(get_db)):
    """Return the PDF report file for a scan."""
    scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return generate_pdf_report(scan)


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan result."""
    scan = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return Response(status_code=204)


async def run_analyzers_for_type(input_value: str, input_type: str) -> dict:
    """Dispatch analyzers based on the input type."""
    if input_type == "email":
        tasks = [
            run_analyzer("breaches", check_breaches(input_value, "email")),
            run_analyzer("username_enum", enumerate_username(input_value)),
            run_analyzer("email_reputation", check_email_reputation(input_value)),
            run_analyzer("dorks", run_dork_scan(input_value, "email")),
        ]
    elif input_type == "username":
        tasks = [
            run_analyzer("username_enum", enumerate_username(input_value)),
            run_analyzer("dorks", run_dork_scan(input_value, "username")),
        ]
    elif input_type == "domain":
        tasks = [
            run_analyzer("domain_intel", analyze_domain(input_value)),
            run_analyzer("dorks", run_dork_scan(input_value, "domain")),
        ]
    else:
        raise HTTPException(status_code=400, detail="input_type must be one of email, username, or domain")

    results = {}
    results_list = await asyncio.gather(*tasks)
    for analyzer_name, analyzer_result in results_list:
        results[analyzer_name] = analyzer_result
    return results


async def run_analyzer(name: str, coro) -> tuple:
    """Run an analyzer and wrap its output."""
    try:
        start_time = time.time()
        data = await coro
        execution_time = time.time() - start_time
        return name, {
            "success": True,
            "data": data,
            "execution_time": execution_time,
        }
    except Exception as exc:
        return name, {
            "success": False,
            "error": str(exc),
            "execution_time": 0,
        }
