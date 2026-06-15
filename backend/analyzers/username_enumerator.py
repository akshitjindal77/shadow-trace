"""
ShadowTrace Username Enumerator

Checks if a username exists across 37+ online platforms by making
concurrent HTTP requests and analyzing response patterns.
"""
import asyncio
import httpx
from typing import List, Dict, Optional, Any

# Phrases that reliably indicate a profile does not exist across any platform
UNIVERSAL_NOT_FOUND_INDICATORS = [
    "page not found",
    "user not found",
    "account not found",
    "profile not found",
    "this page doesn't exist",
    "this page does not exist",
    "this account doesn't exist",
    "this account does not exist",
    "sorry, this page isn't available",
    "the page you were looking for doesn't exist",
    "the page you're looking for doesn't exist",
    "we couldn't find that page",
]

# Realistic user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
]

# Platform definitions with URL patterns and detection logic
PLATFORMS = {
    "github": {
        "url": "https://github.com/{username}",
        "not_found_indicators": ["404", "this is not the web page you are looking for"]
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "not_found_indicators": ["page not found", "404", "this subreddit does not exist"]
    },
    "x": {
        "url": "https://x.com/{username}",
        "not_found_indicators": ["user not found", "page does not exist", "this account does not exist"]
    },
    "instagram": {
        "url": "https://www.instagram.com/{username}",
        "not_found_indicators": ["user not found", "this page could not be found", "page not found"]
    },
    "linkedin": {
        "url": "https://www.linkedin.com/in/{username}",
        "not_found_indicators": ["page not found", "404", "this profile is not available"]
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{username}",
        "not_found_indicators": ["user not found", "page does not exist", "this user does not exist"]
    },
    "twitch": {
        "url": "https://twitch.tv/{username}",
        "not_found_indicators": ["user not found", "channel not found", "this channel does not exist", "404"]
    },
    "steam": {
        "url": "https://steamcommunity.com/id/{username}",
        "not_found_indicators": ["profile not found", "the specified profile could not be found", "err_invalid_character"]
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "tumblr": {
        "url": "https://{username}.tumblr.com",
        "not_found_indicators": ["does not exist", "page not found", "404"]
    },
    "medium": {
        "url": "https://medium.com/@{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "dev.to": {
        "url": "https://dev.to/{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "hackerrank": {
        "url": "https://www.hackerrank.com/{username}",
        "not_found_indicators": ["user not found", "404", "page does not exist"]
    },
    "leetcode": {
        "url": "https://leetcode.com/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "kaggle": {
        "url": "https://www.kaggle.com/{username}",
        "not_found_indicators": ["page not found", "user not found", "404"]
    },
    "gitlab": {
        "url": "https://gitlab.com/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "bitbucket": {
        "url": "https://bitbucket.org/{username}",
        "not_found_indicators": ["page not found", "404", "this account does not exist"]
    },
    "npm": {
        "url": "https://www.npmjs.com/~{username}",
        "not_found_indicators": ["page not found", "404", "not found"]
    },
    "pypi": {
        "url": "https://pypi.org/user/{username}",
        "not_found_indicators": ["page not found", "404", "not found"]
    },
    "docker_hub": {
        "url": "https://hub.docker.com/u/{username}",
        "not_found_indicators": ["page not found", "user not found", "404"]
    },
    "youtube": {
        "url": "https://www.youtube.com/@{username}",
        "not_found_indicators": ["page not found", "404", "channel does not exist"]
    },
    "flickr": {
        "url": "https://www.flickr.com/photos/{username}",
        "not_found_indicators": ["page not found", "404", "this photostream does not exist"]
    },
    "vimeo": {
        "url": "https://vimeo.com/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "soundcloud": {
        "url": "https://soundcloud.com/{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "spotify": {
        "url": "https://open.spotify.com/user/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "lastfm": {
        "url": "https://www.last.fm/user/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "goodreads": {
        "url": "https://www.goodreads.com/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "producthunt": {
        "url": "https://www.producthunt.com/@{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "angellist": {
        "url": "https://angel.co/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "keybase": {
        "url": "https://keybase.io/{username}",
        "not_found_indicators": ["page not found", "404", "not found"]
    },
    "gravatar": {
        "url": "https://gravatar.com/{username}",
        "not_found_indicators": ["page not found", "404", "not found"]
    },
    "about_me": {
        "url": "https://about.me/{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "replit": {
        "url": "https://replit.com/@{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "codepen": {
        "url": "https://codepen.io/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "dribbble": {
        "url": "https://dribbble.com/{username}",
        "not_found_indicators": ["page not found", "404", "user not found"]
    },
    "behance": {
        "url": "https://www.behance.net/{username}",
        "not_found_indicators": ["page not found", "404", "user does not exist"]
    },
    "fiverr": {
        "url": "https://www.fiverr.com/{username}",
        "not_found_indicators": ["page not found", "404", "seller not found"]
    },
    "upwork": {
        "url": "https://www.upwork.com/o/{username}",
        "not_found_indicators": ["page not found", "404", "freelancer not found"]
    }
}


async def check_platform(
    client: httpx.AsyncClient,
    platform_name: str,
    platform_info: Dict[str, Any],
    username: str
) -> Dict[str, Any]:
    """
    Check if a username exists on a single platform.
    Uses content-based detection with "not found" indicators.
    
    Args:
        client: httpx AsyncClient instance
        platform_name: Name of the platform
        platform_info: Platform configuration dictionary
        username: Username to check
    
    Returns:
        Dictionary with platform check results
    """
    try:
        url = platform_info["url"].format(username=username)
        
        response = await client.get(
            url,
            timeout=5.0,
            follow_redirects=True,
            headers={
                "User-Agent": USER_AGENTS[0]
            }
        )
        
        # Content-based detection: combine platform-specific and universal not-found phrases
        response_text = response.text.lower()
        platform_indicators = platform_info.get("not_found_indicators", [])
        all_indicators = list(platform_indicators) + UNIVERSAL_NOT_FOUND_INDICATORS

        found = True
        for indicator in all_indicators:
            if indicator.lower() in response_text:
                found = False
                break

        # Also check for specific HTTP status codes that indicate not found
        if response.status_code in [404, 410]:
            found = False
        
        return {
            "platform": platform_name,
            "url": url,
            "found": found,
            "profile_url": url if found else None,
            "status_code": response.status_code,
            "error": None
        }
    
    except httpx.TimeoutException:
        return {
            "platform": platform_name,
            "url": platform_info["url"].format(username=username),
            "found": False,
            "profile_url": None,
            "status_code": None,
            "error": "timeout"
        }
    
    except httpx.ConnectError:
        return {
            "platform": platform_name,
            "url": platform_info["url"].format(username=username),
            "found": False,
            "profile_url": None,
            "status_code": None,
            "error": "connection_error"
        }
    
    except Exception as e:
        return {
            "platform": platform_name,
            "url": platform_info["url"].format(username=username),
            "found": False,
            "profile_url": None,
            "status_code": None,
            "error": str(e)
        }


async def enumerate_username(username: str) -> Dict[str, Any]:
    """
    Check if a username exists across 37+ online platforms.
    
    Runs all platform checks concurrently to minimize execution time.
    Handles connection errors per platform without stopping other checks.
    
    Args:
        username: Username to enumerate across platforms
    
    Returns:
        Dictionary containing:
            - username: The username checked
            - platforms_found: Number of platforms where username exists
            - platforms: List of platform check results
            - error: Any errors encountered during enumeration
    """
    if not username or len(username) < 1:
        return {
            "username": username,
            "platforms_found": 0,
            "platforms": [],
            "error": "Username too short or empty"
        }
    
    # Sanitize username
    username = username.strip().replace(" ", "").lower()
    
    # Extract email prefix if input is an email address
    if "@" in username:
        username = username.split("@")[0]
    
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # Create concurrent tasks for all platforms
            tasks = [
                check_platform(client, platform_name, platform_info, username)
                for platform_name, platform_info in PLATFORMS.items()
            ]
            
            # Run all checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and valid results
            platform_results = []
            platforms_found = 0
            
            for result in results:
                if isinstance(result, Exception):
                    continue
                platform_results.append(result)
                if result.get("found"):
                    platforms_found += 1
            
            return {
                "username": username,
                "platforms_found": platforms_found,
                "total_platforms_checked": len(PLATFORMS),
                "platforms": platform_results,
                "error": None
            }
    
    except Exception as e:
        return {
            "username": username,
            "platforms_found": 0,
            "platforms": [],
            "error": f"Enumeration error: {str(e)}"
        }


# Test code
if __name__ == "__main__":
    import asyncio
    
    async def test_username_enumerator():
        print("=" * 80)
        print("Testing Username Enumerator Module")
        print("=" * 80)
        
        # Test with a common username
        test_username = "john"
        print(f"\nEnumerating username: {test_username}")
        print("This may take a minute as it checks 37+ platforms concurrently...\n")
        
        result = await enumerate_username(test_username)
        
        print(f"Username: {result['username']}")
        print(f"Platforms Found: {result['platforms_found']} out of {result['total_platforms_checked']}")
        print(f"Error: {result['error']}")
        
        print("\n" + "-" * 80)
        print("Platform Results (Found only):")
        print("-" * 80)
        
        found_platforms = [p for p in result['platforms'] if p['found']]
        if found_platforms:
            for platform in found_platforms:
                print(f"✓ {platform['platform']}: {platform['profile_url']}")
        else:
            print("No platforms found with this username.")
        
        print("\n" + "=" * 80)
    
    asyncio.run(test_username_enumerator())
