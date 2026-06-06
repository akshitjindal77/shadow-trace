"""
ShadowTrace Database Models

Defines SQLAlchemy ORM models for storing scan results.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON
from backend.database.db import Base


class ScanResult(Base):
    """Model for storing completed scan results."""
    
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Input information
    query_input = Column(String(255), index=True, nullable=False)  # Email, username, or domain
    query_type = Column(String(50), nullable=False)  # email, username, domain
    
    # Risk scoring
    risk_score = Column(Float, nullable=False)  # 0-100
    risk_level = Column(String(20), nullable=False)  # critical, high, medium, low, minimal
    
    # Results
    breaches_found = Column(Integer, default=0)
    platforms_found = Column(Integer, default=0)
    email_reputation_score = Column(Float, nullable=True)
    domain_info = Column(JSON, nullable=True)
    social_footprint = Column(JSON, nullable=True)
    dork_results = Column(JSON, nullable=True)
    
    # Recommendations
    recommendations = Column(JSON, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    
    # Full scan data (for export/history)
    full_results = Column(JSON, nullable=True)
    
    def __repr__(self):
        return f"<ScanResult(id={self.id}, query_input={self.query_input}, risk_score={self.risk_score})>"
