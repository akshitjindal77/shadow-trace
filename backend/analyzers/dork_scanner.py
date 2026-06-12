"""
ShadowTrace Dork Scanner

Uses DuckDuckGo HTML search scraping to identify indexed exposure for emails,
usernames, and domains.
"""
import asyncio
from typing import Any, Dict, List
from urllib.parse import quote_plus

import httpx
from bs4 import BeautifulSoup
from backend.config import get_settings

settings = get_settings()
SEARCH_URL = "https://html.duckduckgo.com/html/"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
BRAVE_SEARCH_URL = settings.BRAVE_SEARCH_URL

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://duckduckgo.com/",
    "Connection": "keep-alive"
}

DORK_QUERIES = {
    "email": [
        "{query} site:pastebin.com",
        "{query} filetype:pdf OR filetype:xls OR filetype:csv",
        "{query} password OR leaked OR breach",
        "{query} site:github.com"
    ],
    "username": [
        "{query} site:pastebin.com",
        "{query} leaked OR doxxed",
        "intitle:\"{query}\" profile"
    ],
    "domain": [
        "site:{query} filetype:pdf OR filetype:doc",
        "site:{query} inurl:admin OR inurl:login OR inurl:dashboard",
        "\"{query}\" credentials OR password OR leaked"
    ]
}

HIGH_RISK_KEYWORDS = ["pastebin", "leaked", "credentials", "password", "breach", "doxxed"]
MEDIUM_RISK_KEYWORDS = ["filetype:pdf", "filetype:doc", "filetype:xls", "filetype:csv"]


def _parse_search_results(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    results: List[Dict[str, Any]] = []

    # DuckDuckGo HTML search uses result links and titles in `a.result__a`
    anchors = soup.select("a.result__a")
    for anchor in anchors[:10]:
        title_text = anchor.get_text(strip=True)
        href = anchor.get("href") or ""
        if not title_text and not href:
            continue
        results.append({
            "title": title_text,
            "url": href
        })

    # Fallback: generic anchors if none found
    if not results:
        for link in soup.find_all("a", href=True)[:10]:
            title_text = link.get_text(strip=True)
            href = link["href"]
            if title_text and href:
                results.append({"title": title_text, "url": href})

    return results


def _determine_risk_level(query: str, results: List[Dict[str, Any]]) -> str:
    query_lower = query.lower()
    if any(keyword in query_lower for keyword in HIGH_RISK_KEYWORDS):
        return "HIGH"
    if any(keyword in query_lower for keyword in MEDIUM_RISK_KEYWORDS):
        return "MEDIUM"
    if results:
        return "LOW"
    return "LOW"


def _parse_brave_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    candidates = payload.get("results") or payload.get("web", {}).get("results") or payload.get("data") or []
    for item in candidates[:10]:
        title = item.get("title") or item.get("display_title") or item.get("text")
        url = item.get("url") or item.get("link") or item.get("source")
        if title and url:
            results.append({"title": title, "url": url})
    return results


async def _search_query(client: httpx.AsyncClient, query: str) -> Dict[str, Any]:
    if settings.BRAVE_API_KEY:
        return await _search_query_brave(client, query)
    return await _search_query_duckduckgo(client, query)


async def _search_query_brave(client: httpx.AsyncClient, query: str) -> Dict[str, Any]:
    params = {"q": query, "size": 10}
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Authorization": f"Bearer {settings.BRAVE_API_KEY}"
    }

    try:
        response = await client.get(BRAVE_SEARCH_URL, headers=headers, params=params)
        response.raise_for_status()
        payload = response.json()
        results = _parse_brave_results(payload)
        risk_level = _determine_risk_level(query, results)
        return {
            "query_string": query,
            "results_found": len(results) > 0,
            "result_count": len(results),
            "top_3_results": results[:3],
            "risk_level": risk_level,
            "source": "brave"
        }
    except httpx.HTTPStatusError as exc:
        return {
            "query_string": query,
            "results_found": False,
            "result_count": 0,
            "top_3_results": [],
            "risk_level": "LOW",
            "error": f"HTTP {exc.response.status_code}",
            "source": "brave"
        }
    except Exception as exc:
        return {
            "query_string": query,
            "results_found": False,
            "result_count": 0,
            "top_3_results": [],
            "risk_level": "LOW",
            "error": str(exc),
            "source": "brave"
        }


async def _search_query_duckduckgo(client: httpx.AsyncClient, query: str) -> Dict[str, Any]:
    encoded = quote_plus(query)
    url = f"{SEARCH_URL}?q={encoded}"
    await asyncio.sleep(2)

    try:
        response = await client.get(url, headers=DEFAULT_HEADERS)
        response.raise_for_status()
        results = _parse_search_results(response.text)
        risk_level = _determine_risk_level(query, results)
        return {
            "query_string": query,
            "results_found": len(results) > 0,
            "result_count": len(results),
            "top_3_results": results[:3],
            "risk_level": risk_level,
            "source": "duckduckgo"
        }
    except httpx.HTTPStatusError as exc:
        return {
            "query_string": query,
            "results_found": False,
            "result_count": 0,
            "top_3_results": [],
            "risk_level": "LOW",
            "error": f"HTTP {exc.response.status_code}",
            "source": "duckduckgo"
        }
    except Exception as exc:
        return {
            "query_string": query,
            "results_found": False,
            "result_count": 0,
            "top_3_results": [],
            "risk_level": "LOW",
            "error": str(exc),
            "source": "duckduckgo"
        }


async def run_dork_scan(query: str, scan_type: str) -> Dict[str, Any]:
    scan_type = scan_type.lower()
    if scan_type not in DORK_QUERIES:
        return {
            "query": query,
            "scan_type": scan_type,
            "queries": [],
            "error": "Unsupported scan_type"
        }

    query_text = query.strip()
    if not query_text:
        return {
            "query": query_text,
            "scan_type": scan_type,
            "queries": [],
            "error": "Query cannot be empty"
        }

    tasks = []
    async with httpx.AsyncClient(timeout=20.0) as client:
        for template in DORK_QUERIES[scan_type]:
            formatted = template.format(query=query_text)
            tasks.append(_search_query(client, formatted))
        results = await asyncio.gather(*tasks)

    return {
        "query": query_text,
        "scan_type": scan_type,
        "queries": results
    }


if __name__ == "__main__":
    import asyncio

    async def test_dork_scanner():
        print("=" * 60)
        print("Testing Dork Scanner Module")
        print("=" * 60)

        for scan_type, sample_query in [
            ("email", "test@example.com"),
            ("username", "johnsmith"),
            ("domain", "example.com")
        ]:
            print(f"\nRunning {scan_type} dork scan for: {sample_query}")
            result = await run_dork_scan(sample_query, scan_type)
            print(result)

        print("\nTests completed.")
        print("=" * 60)

    asyncio.run(test_dork_scanner())
