"""
ShadowTrace Database Models

Defines SQLAlchemy ORM models for storing scan results.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from backend.database.db import Base


class ScanResult(Base):
    """Model for storing completed scan results."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), unique=True, index=True, nullable=False)
    input_value = Column(String(255), nullable=False)
    input_type = Column(String(20), nullable=False)
    scan_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    overall_risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    breach_count = Column(Integer, default=0)
    platforms_found = Column(Integer, default=0)
    dork_results_count = Column(Integer, default=0)
    findings_json = Column(Text, nullable=False)
    recommendations_json = Column(Text, nullable=False)
    pdf_report_path = Column(String(512), nullable=True)
    scan_duration_seconds = Column(Float, nullable=False)

    def __repr__(self):
        return (
            f"<ScanResult(id={self.id}, scan_id={self.scan_id}, "
            f"input_value={self.input_value}, overall_risk_score={self.overall_risk_score})>"
        )

    @property
    def risk_score(self) -> float:
        return self.overall_risk_score
