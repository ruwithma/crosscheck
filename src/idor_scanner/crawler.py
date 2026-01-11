import asyncio
import logging
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from .models import Endpoint, HttpMethod, ResourceID, IDType
from .discovery import ID_PATTERNS
from .har_importer import HARImporter

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Request
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class HeadlessCrawler:
    """
    Headless browser crawler using Playwright to capture API traffic.
    Simulates a real user to trigger dynamic API endpoints.
    """
    
    def __init__(self, target: str, headless: bool = True):
        self.target = target
        self.headless = headless
        self.endpoints: List[Endpoint] = []
        self._har_importer = HARImporter(target_domain=urlparse(target).netloc)

    async def crawl(self, cookies: Dict[str, str], timeout: int = 30) -> List[Endpoint]:
        """
        Crawl the target with a headless browser and capture endpoints.
        
        Args:
            cookies: Dictionary of cookies to authenticate
            timeout: Max time to wait for page load and network idle
            
        Returns:
            List of discovered Endpoint objects
        """
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("Playwright not installed. Traffic learning disabled.")
            logger.error("Install with: pip install playwright && playwright install")
            return []

        logger.info("Starting headless crawler...")
        endpoints_found = 0
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            
            # Create context with appropriate cookies
            # Playwright expects list of dicts for cookies check domain
            domain = urlparse(self.target).hostname
            pw_cookies = []
            for k, v in cookies.items():
                pw_cookies.append({
                    "name": k,
                    "value": v,
                    "domain": domain,
                    "path": "/"
                })
                
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                viewport={"width": 1280, "height": 720}
            )
            await context.add_cookies(pw_cookies)
            
            page = await context.new_page()
            
            # Set up request interception
            page.on("request", self._handle_request)
            
            try:
                logger.info(f"Navigating to {self.target}...")
                await page.goto(self.target, wait_until="networkidle", timeout=timeout * 1000)
                
                # Scroll to bottom to trigger lazy loading
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await page.wait_for_timeout(2000) # Wait for extra requests
                
                endpoints_found = len(self.endpoints)
                logger.info(f"Crawler finished. Found {endpoints_found} endpoints.")
                
            except Exception as e:
                logger.error(f"Crawler error: {e}")
            finally:
                await browser.close()
                
        return self.endpoints

    async def _handle_request(self, request: "Request"):
        """Handle intercepted request."""
        # Filter static assets
        url = request.url
        if not url.startswith(self.target):
            # Maybe relax this for subdomains? 
            # ideally check domain scope
            pass
            
        if request.resource_type in ["image", "font", "stylesheet"]:
            return

        # Convert to HAR-like entry for reuse or process directly
        # We can just construct the Endpoint manually to avoid full HAR structure overhead
        
        method = request.method
        
        # Analyze Body if JSON
        body_template = None
        resource_ids = []
        
        # Extract from URL
        path = urlparse(url).path
        import re
        for pattern, id_type in ID_PATTERNS:
            if id_type in [IDType.QUERY_NUMERIC, IDType.QUERY_STRING]:
                continue
            matches = list(re.finditer(pattern, path))
            for match in matches:
                val = match.group(1)
                resource_ids.append(ResourceID(
                    value=val,
                    id_type=id_type,
                    position=match.start(1)
                ))
        
        # Extract from Body
        try:
            post_data = request.post_data
            if post_data and ("application/json" in request.headers.get("content-type", "").lower() or "application/json" in request.headers.get("Content-Type", "").lower()):
                # We need to parse JSON. 
                data = json.loads(post_data)
                # Reuse HARImporter logic? 
                # Yes, but it's private. Let's duplicate or make public.
                # Just duplication for simplicity now as it was a complex method.
                # Actually, I can call the private method, python allows it.
                body_template, body_ids = self._har_importer._analyze_json_body(data)
                if body_ids:
                    resource_ids.extend(body_ids)
        except Exception:
            pass

        # Add endpoint if valid API call
        # Heuristic: JSON content type or has IDs
        is_api = "json" in request.headers.get("accept", "").lower() or \
                 "json" in request.headers.get("content-type", "").lower() or \
                 len(resource_ids) > 0 or \
                 "/api/" in url
                 
        if is_api:
            ep = Endpoint(
                path=path,
                method=HttpMethod(method.upper()),
                resource_ids=resource_ids,
                body_template=body_template,
                description="Discovered via Headless Crawler"
            )
            self.endpoints.append(ep)
