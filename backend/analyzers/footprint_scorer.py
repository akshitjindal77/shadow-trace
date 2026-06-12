"""
ShadowTrace Footprint Scorer

Generates an overall risk score and recommendation list based on scan results.
"""
from typing import Any, Dict, List


def _evaluate_breach_risk(breaches: List[Dict[str, Any]]) -> int:
    count = len(breaches)
    score = 0
    if count == 0:
        score = 0
    elif 1 <= count <= 2:
        score = 15
    elif 3 <= count <= 5:
        score = 25
    else:
        score = 35

    sensitive_bonus = 0
    for breach in breaches:
        data_classes = breach.get("data_classes", [])
        lower_items = [str(item).lower() for item in data_classes]
        if any(any(term in item for term in ("password", "credit", "financial", "ssn", "bank", "card")) for item in lower_items):
            sensitive_bonus = 10
            break

    return min(35, score + sensitive_bonus)


def _evaluate_platform_exposure(platforms_found: int) -> int:
    if platforms_found <= 5:
        return 5
    if platforms_found <= 15:
        return 15
    if platforms_found <= 30:
        return 20
    return 25


def _evaluate_indexed_risk(dork_queries: List[Dict[str, Any]]) -> int:
    score = 0
    found_pastebin = any("pastebin" in q.get("query_string", "").lower() and q.get("results_found") for q in dork_queries)
    found_leaked = any(any(keyword in q.get("query_string", "").lower() for keyword in ("leaked", "breach", "credentials", "password")) and q.get("results_found") for q in dork_queries)
    found_credentials = any("credentials" in q.get("query_string", "").lower() and q.get("results_found") for q in dork_queries)

    if found_pastebin:
        score = max(score, 15)
    if found_leaked:
        score = max(score, 20)
    if found_credentials:
        score = max(score, 25)

    return score


def _evaluate_domain_email_exposure(findings: Dict[str, Any]) -> int:
    score = 0
    email_reputation = findings.get("email_reputation", {})
    domain_intel = findings.get("domain_intel", {})

    spf_exists = email_reputation.get("spf", {}).get("exists")
    dmarc_exists = email_reputation.get("dmarc", {}).get("exists")
    whois_private = domain_intel.get("whois", {}).get("privacy_protection")
    ssl_expiring = domain_intel.get("ssl", {}).get("expires_within_30_days")

    if not spf_exists:
        score += 5
    if not dmarc_exists:
        score += 5
    if whois_private is False:
        score += 3
    if ssl_expiring:
        score += 2

    return min(15, score)


def _build_recommendations(findings: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    breaches = findings.get("breaches", {}).get("breaches") or []
    username_enum = findings.get("username_enum", {}).get("data", {})
    email_rep = findings.get("email_reputation", {})
    domain_intel = findings.get("domain_intel", {})
    dork_results = findings.get("dorks", {}).get("queries") or []

    if breaches:
        recs.append({
            "priority": 1,
            "action": "Change breached passwords immediately",
            "reason": "Your email is associated with known data breaches, increasing account takeover risk.",
            "category": "breach"
        })
    if email_rep.get("is_disposable"):
        recs.append({
            "priority": 2,
            "action": "Stop using disposable email addresses for important services",
            "reason": "Disposable emails are less secure and often blocked by legitimate providers.",
            "category": "email"
        })
    if not email_rep.get("spf", {}).get("exists"):
        recs.append({
            "priority": 2,
            "action": "Publish a valid SPF record for your email domain",
            "reason": "SPF protects your domain from spoofing and improves email deliverability.",
            "category": "email"
        })
    if not email_rep.get("dmarc", {}).get("exists"):
        recs.append({
            "priority": 2,
            "action": "Add a DMARC record to your domain",
            "reason": "DMARC helps prevent phishing and unauthorized use of your email domain.",
            "category": "email"
        })
    if domain_intel.get("whois", {}).get("privacy_protection") is False:
        recs.append({
            "priority": 3,
            "action": "Enable WHOIS privacy protection",
            "reason": "Public WHOIS records expose your contact details and raise privacy risk.",
            "category": "domain"
        })
    if domain_intel.get("ssl", {}).get("expires_within_30_days"):
        recs.append({
            "priority": 3,
            "action": "Renew your SSL certificate before expiration",
            "reason": "Expiring certificates can break trust and make your site vulnerable.",
            "category": "domain"
        })
    if username_enum.get("platforms_found", 0) > 15:
        recs.append({
            "priority": 3,
            "action": "Review online accounts tied to your username",
            "reason": "High platform exposure increases your digital footprint and attack surface.",
            "category": "platform"
        })
    if any(q.get("risk_level") == "HIGH" for q in dork_results):
        recs.append({
            "priority": 1,
            "action": "Investigate high-risk indexed search results",
            "reason": "High-risk results indicate exposed credentials or leaked data linked to your identity.",
            "category": "domain"
        })
    if not recs:
        recs.append({
            "priority": 5,
            "action": "Continue monitoring your digital footprint regularly",
            "reason": "Ongoing monitoring helps catch exposures before they escalate.",
            "category": "platform"
        })

    return sorted(recs, key=lambda item: item["priority"])


def calculate_risk_score(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    breaches = scan_results.get("breaches", {}).get("breaches") or []
    platforms_found = scan_results.get("username_enum", {}).get("data", {}).get("platforms_found", 0)
    dork_queries = scan_results.get("dorks", {}).get("queries") or []

    breach_score = _evaluate_breach_risk(breaches)
    platform_score = _evaluate_platform_exposure(platforms_found)
    indexed_score = _evaluate_indexed_risk(dork_queries)
    domain_email_score = _evaluate_domain_email_exposure(scan_results)

    overall_score = min(100, breach_score + platform_score + indexed_score + domain_email_score)

    if overall_score <= 20:
        risk_level = "LOW"
    elif overall_score <= 40:
        risk_level = "MODERATE"
    elif overall_score <= 70:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "breakdown": {
            "breach_risk": breach_score,
            "platform_exposure": platform_score,
            "indexed_data_risk": indexed_score,
            "domain_email_exposure": domain_email_score
        },
        "recommendations": _build_recommendations(scan_results)
    }


if __name__ == "__main__":
    sample_scan_results = {
        "breaches": {
            "breaches": [
                {"data_classes": ["Email addresses", "Passwords"]},
                {"data_classes": ["Names", "Usernames"]}
            ]
        },
        "username_enum": {"data": {"platforms_found": 18}},
        "dorks": {"queries": [
            {"query_string": "test@example.com site:pastebin.com", "results_found": True, "risk_level": "HIGH"},
            {"query_string": "example.com filetype:pdf", "results_found": True, "risk_level": "MEDIUM"}
        ]},
        "email_reputation": {"spf": {"exists": False}, "dmarc": {"exists": False}, "is_disposable": False},
        "domain_intel": {"whois": {"privacy_protection": False}, "ssl": {"expires_within_30_days": True}}
    }

    result = calculate_risk_score(sample_scan_results)
    print(result)
