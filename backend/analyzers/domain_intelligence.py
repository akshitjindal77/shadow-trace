"""
ShadowTrace Domain Intelligence Analyzer

Collects DNS, WHOIS, IP abuse, and SSL certificate intelligence for a domain.
"""
import asyncio
import ssl
import socket
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import dns.resolver
import httpx
import whois
from backend.config import get_settings

settings = get_settings()

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


async def _resolve_records(domain: str) -> Dict[str, Any]:
    """Resolve DNS records for a domain using dnspython."""
    records: Dict[str, Any] = {
        "A": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": []
    }

    async def query(record_type: str):
        try:
            answers = await asyncio.to_thread(dns.resolver.resolve, domain, record_type, lifetime=10)
            return answers
        except Exception:
            return None

    tasks = {
        record_type: asyncio.create_task(query(record_type))
        for record_type in records
    }

    for record_type, task in tasks.items():
        answers = await task
        if answers is None:
            continue

        if record_type == "A":
            records["A"] = [str(rdata) for rdata in answers]
        elif record_type == "MX":
            records["MX"] = [str(rdata.exchange).rstrip('.') for rdata in answers]
        elif record_type == "TXT":
            parsed = []
            for rdata in answers:
                try:
                    part = b"".join(rdata.strings).decode(errors="ignore")
                except Exception:
                    part = " ".join([s.decode(errors="ignore") for s in rdata.strings if isinstance(s, bytes)])
                parsed.append(part)
            records["TXT"] = parsed
        elif record_type == "NS":
            records["NS"] = [str(rdata.target).rstrip('.') for rdata in answers]
        elif record_type == "CNAME":
            records["CNAME"] = [str(rdata.target).rstrip('.') for rdata in answers]

    return records


async def _analyze_whois(domain: str) -> Dict[str, Any]:
    """Collect WHOIS data for a domain."""
    try:
        raw = await asyncio.to_thread(whois.whois, domain)
    except Exception as exc:
        return {
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "registrant_country": None,
            "privacy_protection": False,
            "error": str(exc)
        }

    def _normalize_date(value: Any) -> Optional[str]:
        if isinstance(value, list):
            value = value[0]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return value
        return None

    registrant_name = getattr(raw, "name", "") or ""
    privacy_protection = any(
        term in registrant_name.lower()
        for term in ("privacy", "proxy", "redacted")
    )

    return {
        "registrar": getattr(raw, "registrar", None),
        "creation_date": _normalize_date(getattr(raw, "creation_date", None)),
        "expiration_date": _normalize_date(getattr(raw, "expiration_date", None)),
        "registrant_country": getattr(raw, "country", None),
        "privacy_protection": privacy_protection,
        "error": None
    }


async def _check_abuseipdb(ip_address: str) -> Dict[str, Any]:
    """Query AbuseIPDB for abuse intelligence on an IP."""
    if not settings.ABUSEIPDB_API_KEY:
        return {
            "ip": ip_address,
            "abuse_confidence_score": None,
            "country": None,
            "isp": None,
            "total_reports": None,
            "status": "missing_api_key"
        }

    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
        "User-Agent": "ShadowTrace-DomainIntelligence"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ABUSEIPDB_BASE_URL, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "ip": ip_address,
                    "abuse_confidence_score": data.get("abuseConfidenceScore"),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "total_reports": data.get("totalReports"),
                    "status": "success"
                }
            return {
                "ip": ip_address,
                "abuse_confidence_score": None,
                "country": None,
                "isp": None,
                "total_reports": None,
                "status": f"http_{response.status_code}"
            }
    except Exception as exc:
        return {
            "ip": ip_address,
            "abuse_confidence_score": None,
            "country": None,
            "isp": None,
            "total_reports": None,
            "status": "error",
            "error": str(exc)
        }


async def _check_ssl_certificate(domain: str) -> Dict[str, Any]:
    """Retrieve SSL certificate details for the domain."""
    context = ssl.create_default_context()
    issuer = None
    not_after = None

    try:
        loop = asyncio.get_running_loop()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer = issuer.get("organizationName") or issuer.get("commonName")
                not_after = cert.get("notAfter")

        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") if not_after else None
        days_until_expiry = None
        expires_within_30_days = None
        if expiry_date:
            delta = expiry_date - datetime.utcnow()
            days_until_expiry = delta.days
            expires_within_30_days = delta <= timedelta(days=30)

        return {
            "issuer": issuer,
            "expiry_date": expiry_date.isoformat() if expiry_date else None,
            "days_until_expiry": days_until_expiry,
            "expires_within_30_days": expires_within_30_days,
            "status": "success"
        }
    except Exception as exc:
        return {
            "issuer": None,
            "expiry_date": None,
            "days_until_expiry": None,
            "expires_within_30_days": None,
            "status": "error",
            "error": str(exc)
        }


async def analyze_domain(domain: str) -> Dict[str, Any]:
    """Analyze a domain across DNS, WHOIS, IP intelligence, and SSL."""
    domain = domain.strip().lower()
    if not domain:
        return {
            "domain": domain,
            "dns": {},
            "whois": {},
            "ip_intelligence": [],
            "ssl": {},
            "error": "Domain is required"
        }

    dns_task = asyncio.create_task(_resolve_records(domain))
    whois_task = asyncio.create_task(_analyze_whois(domain))
    ssl_task = asyncio.create_task(_check_ssl_certificate(domain))

    dns_results = await dns_task
    whois_results = await whois_task
    ssl_results = await ssl_task

    abuse_tasks = []
    for ip_address in dns_results.get("A", []):
        abuse_tasks.append(asyncio.create_task(_check_abuseipdb(ip_address)))

    abuse_results = []
    if abuse_tasks:
        abuse_results = await asyncio.gather(*abuse_tasks)

    return {
        "domain": domain,
        "dns": dns_results,
        "whois": whois_results,
        "ip_intelligence": abuse_results,
        "ssl": ssl_results,
        "error": None
    }


if __name__ == "__main__":
    import asyncio

    async def test_domain_intelligence():
        print("=" * 60)
        print("Testing Domain Intelligence Module")
        print("=" * 60)
        test_domain = "example.com"
        print(f"\nAnalyzing domain: {test_domain}")
        result = await analyze_domain(test_domain)
        print(result)
        print("\nTests completed.")
        print("=" * 60)

    asyncio.run(test_domain_intelligence())
