"""
ShadowTrace Configuration Module

Loads environment variables and provides application settings.
"""
import os
from typing import List
from functools import lru_cache
from dotenv import load_dotenv


class Settings:
    """Application settings loaded from environment variables."""
    
    def __init__(self):
        load_dotenv()
        
        # API Configuration
        self.API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
        self.API_PORT: int = int(os.getenv("API_PORT", "8000"))
        self.DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
        
        # Database
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./shadowtrace.db")
        
        # API Keys
        self.HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")
        self.ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
        self.BRAVE_API_KEY: str = os.getenv("BRAVE_API_KEY", "")
        self.BRAVE_SEARCH_URL: str = os.getenv("BRAVE_SEARCH_URL", "https://api.search.brave.com/res/v1/web")
        
        # Rate Limiting
        self.RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
        self.RATE_LIMIT_PERIOD: int = int(os.getenv("RATE_LIMIT_PERIOD", "3600"))
        
        # CORS
        cors_origins = os.getenv("CORS_ORIGINS", '["http://localhost:3000", "http://127.0.0.1:8000"]')
        try:
            import json
            self.CORS_ORIGINS: List[str] = json.loads(cors_origins)
        except:
            self.CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:8000"]
        
        # External Services Timeouts
        self.DUCKDUCKGO_TIMEOUT: int = int(os.getenv("DUCKDUCKGO_TIMEOUT", "30"))
        self.WHOIS_TIMEOUT: int = int(os.getenv("WHOIS_TIMEOUT", "10"))
        self.DNS_TIMEOUT: int = int(os.getenv("DNS_TIMEOUT", "5"))


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
