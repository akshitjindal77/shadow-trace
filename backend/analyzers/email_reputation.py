"""
ShadowTrace Email Reputation Analyzer

Validates email domains, checks MX/SPF/DMARC records, and calculates a trust score.
"""
import asyncio
import re
from typing import Any, Dict, List, Optional

import dns.resolver
from backend.config import get_settings

settings = get_settings()

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com",
    "throwawaymail.com", "trashmail.com", "maildrop.cc", "yopmail.com",
    "dispostable.com", "mailnesia.com", "fakeinbox.com", "temp-mail.org",
    "getairmail.com", "mintemail.com", "mytemp.email", "spambog.com",
    "mailcatch.com", "mailtemp.net", "e4ward.com", "temp-mail.io",
    "trashmail.net", "trashmail.com", "mail-temporaire.fr", "sharklasers.com",
    "spamgourmet.com", "10minutemail.net", "disposablemail.com", "sharkmail.com",
    "emailondeck.com", "moakt.com"
}

FREE_PROVIDER_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "live.com", "mail.com", "zoho.com"
}

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


async def _lookup_txt_records(domain: str) -> List[str]:
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "TXT", lifetime=10)
        records = []
        for rdata in answers:
            if hasattr(rdata, "strings"):
                try:
                    records.append("".join([part.decode("utf-8", errors="ignore") for part in rdata.strings]))
                except Exception:
                    records.append(str(rdata))
            else:
                records.append(str(rdata))
        return records
    except Exception:
        return []


async def _lookup_mx_records(domain: str) -> List[str]:
    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, domain, "MX", lifetime=10)
        return [str(rdata.exchange).rstrip('.') for rdata in answers]
    except Exception:
        return []


async def _check_spf(domain: str, txt_records: List[str]) -> Dict[str, Any]:
    spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
    valid = len(spf_records) > 0
    return {
        "exists": valid,
        "records": spf_records,
        "valid": valid
    }


async def _check_dmarc(domain: str) -> Dict[str, Any]:
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = await _lookup_txt_records(dmarc_domain)
    dmarc_records = [record for record in txt_records if record.lower().startswith("v=dmarc1")]
    return {
        "exists": len(dmarc_records) > 0,
        "records": dmarc_records
    }


def _calculate_trust_score(findings: Dict[str, Any]) -> int:
    score = 100
    if not findings.get("valid_email"):
        return 0

    if findings.get("is_disposable"):
        score -= 50
    if findings.get("mx_valid") is False:
        score -= 40
    if not findings.get("spf", {}).get("exists"):
        score -= 20
    if not findings.get("dmarc", {}).get("exists"):
        score -= 20
    if findings.get("is_free_provider"):
        score -= 10

    score = max(0, min(100, score))
    return score


async def check_email_reputation(email: str) -> Dict[str, Any]:
    email = email.strip().lower()
    findings: Dict[str, Any] = {
        "email": email,
        "valid_email": False,
        "domain": None,
        "mx_servers": [],
        "mx_valid": False,
        "spf": {"exists": False, "records": [], "valid": False},
        "dmarc": {"exists": False, "records": []},
        "is_disposable": False,
        "is_free_provider": False,
        "trust_score": 0,
        "error": None
    }

    if not EMAIL_REGEX.match(email):
        findings["error"] = "Invalid email format"
        findings["trust_score"] = 0
        return findings

    findings["valid_email"] = True
    domain = email.split("@", 1)[1]
    findings["domain"] = domain

    findings["is_disposable"] = domain in DISPOSABLE_DOMAINS
    findings["is_free_provider"] = domain in FREE_PROVIDER_DOMAINS

    mx_records = await _lookup_mx_records(domain)
    findings["mx_servers"] = mx_records
    findings["mx_valid"] = len(mx_records) > 0

    txt_records = await _lookup_txt_records(domain)
    spf_result = await _check_spf(domain, txt_records)
    dmarc_result = await _check_dmarc(domain)

    findings["spf"] = spf_result
    findings["dmarc"] = dmarc_result
    findings["trust_score"] = _calculate_trust_score(findings)

    return findings


if __name__ == "__main__":
    import asyncio

    async def test_email_reputation():
        print("=" * 60)
        print("Testing Email Reputation Module")
        print("=" * 60)
        
        test_email = "admin@example.com"
        print(f"\nChecking reputation for: {test_email}")
        result = await check_email_reputation(test_email)
        print(result)
        
        print("\nTests completed.")
        print("=" * 60)

    asyncio.run(test_email_reputation())
