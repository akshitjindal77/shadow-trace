"""
ShadowTrace Username Enumerator

Checks if a username exists across 37+ online platforms by making
concurrent HTTP requests and analyzing response patterns.
"""
import asyncio
import httpx
from typing import List, Dict, Optional, Any

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
        "status_code": 200,
        "method": "status"
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "status_code": 200,
        "method": "status"
    },
    "twitter": {
        "url": "https://twitter.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "instagram": {
        "url": "https://www.instagram.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "linkedin": {
        "url": "https://www.linkedin.com/in/{username}",
        "status_code": 200,
        "method": "status"
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{username}",
        "status_code": 200,
        "method": "status"
    },
    "twitch": {
        "url": "https://twitch.tv/{username}",
        "status_code": 200,
        "method": "status"
    },
    "steam": {
        "url": "https://steamcommunity.com/profiles/{username}",
        "status_code": 200,
        "method": "content",
        "check": "steamid"
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "tumblr": {
        "url": "https://{username}.tumblr.com",
        "status_code": 200,
        "method": "status"
    },
    "medium": {
        "url": "https://medium.com/@{username}",
        "status_code": 200,
        "method": "status"
    },
    "dev.to": {
        "url": "https://dev.to/{username}",
        "status_code": 200,
        "method": "status"
    },
    "hackerrank": {
        "url": "https://www.hackerrank.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "leetcode": {
        "url": "https://leetcode.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "kaggle": {
        "url": "https://www.kaggle.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "gitlab": {
        "url": "https://gitlab.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "bitbucket": {
        "url": "https://bitbucket.org/{username}",
        "status_code": 200,
        "method": "status"
    },
    "npm": {
        "url": "https://www.npmjs.com/~{username}",
        "status_code": 200,
        "method": "status"
    },
    "pypi": {
        "url": "https://pypi.org/user/{username}",
        "status_code": 200,
        "method": "status"
    },
    "docker_hub": {
        "url": "https://hub.docker.com/u/{username}",
        "status_code": 200,
        "method": "status"
    },
    "youtube": {
        "url": "https://www.youtube.com/@{username}",
        "status_code": 200,
        "method": "status"
    },
    "flickr": {
        "url": "https://www.flickr.com/photos/{username}",
        "status_code": 200,
        "method": "status"
    },
    "vimeo": {
        "url": "https://vimeo.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "soundcloud": {
        "url": "https://soundcloud.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "spotify": {
        "url": "https://open.spotify.com/user/{username}",
        "status_code": 200,
        "method": "status"
    },
    "lastfm": {
        "url": "https://www.last.fm/user/{username}",
        "status_code": 200,
        "method": "status"
    },
    "goodreads": {
        "url": "https://www.goodreads.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "producthunt": {
        "url": "https://www.producthunt.com/@{username}",
        "status_code": 200,
        "method": "status"
    },
    "angellist": {
        "url": "https://angel.co/{username}",
        "status_code": 200,
        "method": "status"
    },
    "keybase": {
        "url": "https://keybase.io/{username}",
        "status_code": 200,
        "method": "status"
    },
    "gravatar": {
        "url": "https://gravatar.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "about_me": {
        "url": "https://about.me/{username}",
        "status_code": 200,
        "method": "status"
    },
    "pastebin": {
        "url": "https://pastebin.com/u/{username}",
        "status_code": 200,
        "method": "status"
    },
    "replit": {
        "url": "https://replit.com/@{username}",
        "status_code": 200,
        "method": "status"
    },
    "codepen": {
        "url": "https://codepen.io/{username}",
        "status_code": 200,
        "method": "status"
    },
    "dribbble": {
        "url": "https://dribbble.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "behance": {
        "url": "https://www.behance.net/{username}",
        "status_code": 200,
        "method": "status"
    },
    "fiverr": {
        "url": "https://www.fiverr.com/{username}",
        "status_code": 200,
        "method": "status"
    },
    "upwork": {
        "url": "https://www.upwork.com/o/{username}",
        "status_code": 200,
        "method": "status"
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
        
        # Check if username exists based on status code
        found = response.status_code == platform_info.get("status_code", 200)
        
        # Additional content-based checks for specific platforms
        if found and platform_info.get("method") == "content":
            check_string = platform_info.get("check", "")
            found = check_string.lower() in response.text.lower()
        
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
