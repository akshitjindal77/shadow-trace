"""
ShadowTrace Breach Checker

Checks if email addresses or passwords have appeared in known data breaches
using the HaveIBeenPwned API and the k-anonymity password model.
"""
import asyncio
import hashlib
import httpx
from typing import List, Dict, Optional, Any
from backend.config import get_settings

settings = get_settings()

# Rate limiting constant
RATE_LIMIT_DELAY = 1.5  # seconds between requests


async def check_breaches(email: str, query_type: str = "email") -> Dict[str, Any]:
    """
    Check if an email address has appeared in known data breaches.
    
    Uses the HaveIBeenPwned API v3 to query breach data.
    Implements rate limiting (1.5 seconds between requests) to respect API limits.
    
    Args:
        email: Email address to check
        query_type: Type of query (email, username, or domain)
    
    Returns:
        Dictionary containing:
            - breaches: List of breach objects with details
            - breach_count: Total number of breaches found
            - earliest_breach: Date of earliest breach
            - latest_breach: Date of latest breach
    
    Raises:
        Returns gracefully on any HTTP error without crashing
    """
    if not settings.HIBP_API_KEY:
        return {
            "breaches": [],
            "breach_count": 0,
            "error": "HIBP API key not configured",
            "status": "skipped"
        }
    
    # Only check email addresses with HaveIBeenPwned
    if query_type != "email" or "@" not in email:
        return {
            "breaches": [],
            "breach_count": 0,
            "status": "skipped",
            "reason": "HaveIBeenPwned only supports email addresses"
        }
    
    headers = {
        "hibp-api-key": settings.HIBP_API_KEY,
        "User-Agent": "ShadowTrace-DigitalFootprintAnalyzer"
    }
    
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    params = {"truncateResponse": "false"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Implement rate limiting
            await asyncio.sleep(RATE_LIMIT_DELAY)
            
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                # Breaches found
                breaches = response.json()
                
                # Format breach data
                formatted_breaches = []
                dates = []
                
                for breach in breaches:
                    formatted_breach = {
                        "name": breach.get("Name", "Unknown"),
                        "domain": breach.get("Domain", "N/A"),
                        "breach_date": breach.get("BreachDate", "Unknown"),
                        "description": breach.get("Description", "No description"),
                        "data_classes": breach.get("DataClasses", []),
                        "is_verified": breach.get("IsVerified", False),
                        "is_sensitive": breach.get("IsSensitive", False),
                        "is_retired": breach.get("IsRetired", False),
                        "logo_path": breach.get("LogoPath", "")
                    }
                    formatted_breaches.append(formatted_breach)
                    if breach.get("BreachDate"):
                        dates.append(breach.get("BreachDate"))
                
                return {
                    "breaches": formatted_breaches,
                    "breach_count": len(formatted_breaches),
                    "earliest_breach": min(dates) if dates else None,
                    "latest_breach": max(dates) if dates else None,
                    "status": "found"
                }
            
            elif response.status_code == 404:
                # No breaches found (this is a good thing)
                return {
                    "breaches": [],
                    "breach_count": 0,
                    "status": "clean",
                    "message": "Email not found in known breaches"
                }
            
            elif response.status_code == 429:
                # Rate limited by API
                return {
                    "breaches": [],
                    "breach_count": 0,
                    "status": "rate_limited",
                    "error": "HaveIBeenPwned API rate limit exceeded. Try again later."
                }
            
            else:
                # Other HTTP errors
                return {
                    "breaches": [],
                    "breach_count": 0,
                    "status": "error",
                    "error": f"API returned status code {response.status_code}"
                }
    
    except httpx.TimeoutException:
        return {
            "breaches": [],
            "breach_count": 0,
            "status": "timeout",
            "error": "Request to HaveIBeenPwned API timed out"
        }
    
    except httpx.ConnectError:
        return {
            "breaches": [],
            "breach_count": 0,
            "status": "connection_error",
            "error": "Failed to connect to HaveIBeenPwned API"
        }
    
    except Exception as e:
        return {
            "breaches": [],
            "breach_count": 0,
            "status": "error",
            "error": f"Unexpected error: {str(e)}"
        }


async def check_password_pwned(password: str) -> Dict[str, Any]:
    """
    Check if a password appears in known breach databases using k-anonymity.
    
    This uses the k-anonymity model which checks only the first 5 characters
    of the SHA-1 hash, never exposing the full password or hash.
    
    Args:
        password: Password to check (in plaintext)
    
    Returns:
        Dictionary containing:
            - is_pwned: Boolean indicating if password appears in breaches
            - pwned_count: Number of times password appears in known breaches
            - status: Status of the check
    """
    try:
        # Create SHA-1 hash of password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        # Use only first 5 characters (k-anonymity)
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        headers = {
            "User-Agent": "ShadowTrace-DigitalFootprintAnalyzer"
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                # Parse the response
                lines = response.text.split('\n')
                
                # Search for matching suffix
                for line in lines:
                    parts = line.split(':')
                    if len(parts) == 2:
                        hash_suffix, count = parts[0].strip(), parts[1].strip()
                        if hash_suffix == suffix:
                            return {
                                "is_pwned": True,
                                "pwned_count": int(count),
                                "status": "compromised",
                                "message": f"Password found {count} times in known breaches. Change immediately."
                            }
                
                # Password not found in breaches
                return {
                    "is_pwned": False,
                    "pwned_count": 0,
                    "status": "secure",
                    "message": "Password not found in known breaches"
                }
            
            else:
                return {
                    "is_pwned": None,
                    "pwned_count": 0,
                    "status": "error",
                    "error": f"API returned status code {response.status_code}"
                }
    
    except httpx.TimeoutException:
        return {
            "is_pwned": None,
            "pwned_count": 0,
            "status": "timeout",
            "error": "Request to Pwned Passwords API timed out"
        }
    
    except Exception as e:
        return {
            "is_pwned": None,
            "pwned_count": 0,
            "status": "error",
            "error": f"Unexpected error: {str(e)}"
        }


# Test code
if __name__ == "__main__":
    import asyncio
    from dotenv import load_dotenv
    
    load_dotenv()
    
    async def test_breach_checker():
        print("=" * 60)
        print("Testing Breach Checker Module")
        print("=" * 60)
        
        # Test with a known breached email
        test_email = "test@example.com"
        print(f"\n1. Testing check_breaches with: {test_email}")
        result = await check_breaches(test_email, "email")
        print(f"   Result: {result}")
        
        # Test with a password (be careful with real passwords!)
        test_password = "password123"
        print(f"\n2. Testing check_password_pwned with: {test_password}")
        result = await check_password_pwned(test_password)
        print(f"   Result: {result}")
        
        print("\n" + "=" * 60)
        print("Tests completed!")
        print("=" * 60)
    
    asyncio.run(test_breach_checker())
