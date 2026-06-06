"""
ShadowTrace API Routes

Main API endpoints for scan operations and results.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List
import asyncio
import time
from datetime import datetime

from backend.api.schemas import (
    ScanRequest, ScanResponse, ScanHistoryResponse, ScanDetailResponse, 
    HealthResponse, ReportRequest, AnalysisResult
)
from backend.database.db import get_db
from backend.database.models import ScanResult
from backend.analyzers.breach_checker import check_breaches
from backend.analyzers.username_enumerator import enumerate_usernames
from backend.analyzers.email_reputation import check_email_reputation
from backend.analyzers.domain_intelligence import get_domain_intelligence
from backend.analyzers.dork_scanner import simulate_google_dorks
from backend.analyzers.footprint_scorer import score_social_footprint
from backend.utils.report_generator import generate_pdf_report

router = APIRouter(prefix="/api", tags=["scanning"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(status="healthy", version="1.0.0")


@router.post("/scan", response_model=ScanResponse)
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Initiate a digital footprint scan.
    
    Runs 6 parallel async checks:
    1. Breach check using HaveIBeenPwned API
    2. Username enumeration across platforms
    3. Email reputation check
    4. Domain and IP intelligence
    5. Google dork simulation
    6. Social footprint scoring
    """
    try:
        query = request.query.strip()
        query_type = determine_query_type(query)
        
        # Run all analyzers in parallel
        start_time = time.time()
        results = await run_all_analyzers(query, query_type)
        execution_time = time.time() - start_time
        
        # Calculate risk score
        risk_score, risk_level = calculate_risk_score(results)
        
        # Prepare recommendations
        recommendations = generate_recommendations(results, risk_score)
        
        # Extract specific data
        breaches_found = len(results.get("breaches", {}).get("data", {}).get("breaches", []))
        platforms_found = results.get("username_enum", {}).get("data", {}).get("platforms_found", 0)
        
        # Save to database
        scan_result = ScanResult(
            query_input=query,
            query_type=query_type,
            risk_score=risk_score,
            risk_level=risk_level,
            breaches_found=breaches_found,
            platforms_found=platforms_found,
            email_reputation_score=results.get("email_reputation", {}).get("data", {}).get("score"),
            domain_info=results.get("domain_intel", {}).get("data"),
            social_footprint=results.get("footprint", {}).get("data"),
            dork_results=results.get("dorks", {}).get("data"),
            recommendations=recommendations,
            full_results=results
        )
        db.add(scan_result)
        db.commit()
        db.refresh(scan_result)
        
        return ScanResponse(
            query_input=query,
            query_type=query_type,
            risk_score=risk_score,
            risk_level=risk_level,
            breaches_found=breaches_found,
            platforms_found=platforms_found,
            email_reputation_score=results.get("email_reputation", {}).get("data", {}).get("score"),
            domain_info=results.get("domain_intel", {}).get("data"),
            social_footprint=results.get("footprint", {}).get("data"),
            dork_results=results.get("dorks", {}).get("data"),
            recommendations=recommendations,
            created_at=scan_result.created_at
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/history", response_model=List[ScanHistoryResponse])
async def get_scan_history(db: Session = Depends(get_db)):
    """Get all past scans in chronological order."""
    scans = db.query(ScanResult).order_by(desc(ScanResult.created_at)).all()
    return scans


@router.get("/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Get detailed results of a specific scan."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/report/{scan_id}")
async def generate_report(
    scan_id: int,
    report_request: ReportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Generate PDF or JSON report for a scan."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if report_request.format == "pdf":
        return await generate_pdf_report(scan)
    elif report_request.format == "json":
        return scan.full_results
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan from history."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}


# Helper functions
def determine_query_type(query: str) -> str:
    """Determine if query is email, username, or domain."""
    if "@" in query:
        return "email"
    elif "." in query:
        return "domain"
    else:
        return "username"


async def run_all_analyzers(query: str, query_type: str) -> dict:
    """Run all 6 analyzers in parallel."""
    results = {}
    
    tasks = [
        run_analyzer("breaches", check_breaches(query, query_type)),
        run_analyzer("username_enum", enumerate_usernames(query)),
        run_analyzer("email_reputation", check_email_reputation(query, query_type)),
        run_analyzer("domain_intel", get_domain_intelligence(query, query_type)),
        run_analyzer("dorks", simulate_google_dorks(query)),
        run_analyzer("footprint", score_social_footprint(query, query_type))
    ]
    
    results_list = await asyncio.gather(*tasks)
    for analyzer_name, analyzer_result in results_list:
        results[analyzer_name] = analyzer_result
    
    return results


async def run_analyzer(name: str, coro) -> tuple:
    """Run a single analyzer and track execution time."""
    try:
        start = time.time()
        data = await coro
        execution_time = time.time() - start
        return name, {
            "success": True,
            "data": data,
            "execution_time": execution_time
        }
    except Exception as e:
        return name, {
            "success": False,
            "error": str(e),
            "execution_time": 0
        }


def calculate_risk_score(results: dict) -> tuple:
    """Calculate overall risk score (0-100) and risk level."""
    score = 0
    weights = {
        "breaches": 30,
        "username_enum": 20,
        "email_reputation": 15,
        "domain_intel": 15,
        "dorks": 15,
        "footprint": 5
    }
    
    # Process each analyzer result
    if results.get("breaches", {}).get("success"):
        breaches = len(results["breaches"].get("data", {}).get("breaches", []))
        score += min(weights["breaches"], breaches * 3)
    
    if results.get("username_enum", {}).get("success"):
        platforms = results["username_enum"].get("data", {}).get("platforms_found", 0)
        score += min(weights["username_enum"], platforms * 0.4)
    
    if results.get("email_reputation", {}).get("success"):
        email_score = results["email_reputation"].get("data", {}).get("score", 0)
        score += (email_score / 100) * weights["email_reputation"]
    
    if results.get("domain_intel", {}).get("success"):
        score += weights["domain_intel"] * 0.5
    
    if results.get("dorks", {}).get("success"):
        dorks = len(results["dorks"].get("data", {}).get("results", []))
        score += min(weights["dorks"], dorks * 2)
    
    if results.get("footprint", {}).get("success"):
        footprint_score = results["footprint"].get("data", {}).get("score", 0)
        score += (footprint_score / 100) * weights["footprint"]
    
    risk_score = min(100, score)
    
    if risk_score >= 75:
        risk_level = "critical"
    elif risk_score >= 60:
        risk_level = "high"
    elif risk_score >= 40:
        risk_level = "medium"
    elif risk_score >= 20:
        risk_level = "low"
    else:
        risk_level = "minimal"
    
    return risk_score, risk_level


def generate_recommendations(results: dict, risk_score: float) -> list:
    """Generate actionable recommendations based on scan results."""
    recommendations = []
    
    # Breach recommendations
    if results.get("breaches", {}).get("success"):
        breaches = len(results["breaches"].get("data", {}).get("breaches", []))
        if breaches > 0:
            recommendations.append(f"Your account was found in {breaches} data breach(es). Change passwords immediately.")
    
    # Email reputation recommendations
    if results.get("email_reputation", {}).get("success"):
        email_score = results["email_reputation"].get("data", {}).get("score", 0)
        if email_score > 50:
            recommendations.append("Your email address has poor reputation. Consider using a new email for sensitive services.")
    
    # Username enumeration recommendations
    if results.get("username_enum", {}).get("success"):
        platforms = results["username_enum"].get("data", {}).get("platforms_found", 0)
        if platforms > 10:
            recommendations.append(f"Your username is associated with {platforms} online platforms. Review and remove unused accounts.")
    
    # Domain intelligence recommendations
    if results.get("domain_intel", {}).get("success"):
        recommendations.append("Review your domain registration privacy settings to reduce exposure.")
    
    # General recommendations
    if risk_score >= 75:
        recommendations.append("Enable two-factor authentication (2FA) on all important accounts.")
        recommendations.append("Consider using a password manager to create strong, unique passwords.")
        recommendations.append("Monitor your accounts regularly for suspicious activity.")
    
    if not recommendations:
        recommendations.append("Your digital footprint appears minimal. Continue monitoring regularly.")
    
    return recommendations
