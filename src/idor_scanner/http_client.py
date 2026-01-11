"""
Async HTTP Client for the IDOR Scanner.

Provides a robust HTTP client with retry logic, rate limiting,
timeout handling, and request/response logging.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


class HTTPClientError(Exception):
    """Custom exception for HTTP client errors."""
    pass


class RateLimiter:
    """Simple token bucket rate limiter."""
    
    def __init__(self, requests_per_second: int = 10):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_update = datetime.now()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self._lock:
            now = datetime.now()
            elapsed = (now - self.last_update).total_seconds()
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class HTTPClient:
    """
    Async HTTP client wrapper with advanced features.
    
    Features:
    - Async/await support via httpx
    - Automatic retries with exponential backoff
    - Rate limiting to prevent overwhelming targets
    - Request/response logging
    - Timeout handling
    - SSL/TLS configuration
    """
    
    def __init__(
        self,
        timeout: int = 30,
        rate_limit: int = 10,
        max_retries: int = 3,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.custom_headers = custom_headers or {}
        self.proxy = proxy
        
        self.rate_limiter = RateLimiter(rate_limit)
        self._client: Optional[httpx.AsyncClient] = None
        
        # Request/response history for debugging
        self.history: list = []
        
    async def __aenter__(self) -> "HTTPClient":
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def start(self) -> None:
        """Initialize the HTTP client."""
        if self._client is None:
            # Configure proxies if provided
            proxies = None
            if self.proxy:
                proxies = {
                    "http://": self.proxy,
                    "https://": self.proxy,
                }
                # If using proxy (like Burp), we might need to disable SSL verification
                if not self.verify_ssl:
                    import warnings
                    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
            
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=self.follow_redirects,
                proxy=self.proxy,  # httpx 0.24+ uses 'proxy' not 'proxies'
                headers={
                    "User-Agent": "IDOR-Scanner/1.0.0",
                    **self.custom_headers,
                },
            )
            logger.debug("HTTP client initialized")
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.debug("HTTP client closed")
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """
        Make an HTTP request with retry logic and rate limiting.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Optional headers to include
            cookies: Optional cookies to include
            json: Optional JSON body
            data: Optional form data
            params: Optional query parameters
            
        Returns:
            httpx.Response object
            
        Raises:
            HTTPClientError: If all retries fail
        """
        if self._client is None:
            await self.start()
        
        # Apply rate limiting
        await self.rate_limiter.acquire()
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                start_time = datetime.now()
                
                response = await self._client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    json=json,
                    data=data,
                    params=params,
                )
                
                elapsed = (datetime.now() - start_time).total_seconds()
                
                # Log the request
                self._log_request(method, url, response.status_code, elapsed)
                
                # Store in history
                self.history.append({
                    "timestamp": start_time.isoformat(),
                    "method": method.upper(),
                    "url": url,
                    "status_code": response.status_code,
                    "elapsed_seconds": elapsed,
                    "headers": dict(response.headers),
                })
                
                return response
                
            except httpx.TimeoutException as e:
                last_error = e
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries} for {url}")
                
            except httpx.ConnectError as e:
                last_error = e
                logger.warning(f"Connection error on attempt {attempt + 1}/{self.max_retries} for {url}")
                
            except httpx.HTTPError as e:
                last_error = e
                logger.warning(f"HTTP error on attempt {attempt + 1}/{self.max_retries} for {url}: {e}")
            
            # Exponential backoff
            if attempt < self.max_retries - 1:
                wait_time = (2 ** attempt) + (asyncio.get_event_loop().time() % 1)
                await asyncio.sleep(wait_time)
        
        raise HTTPClientError(f"Request failed after {self.max_retries} attempts: {last_error}")
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make a POST request."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make a PUT request."""
        return await self.request("PUT", url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> httpx.Response:
        """Make a PATCH request."""
        return await self.request("PATCH", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make a DELETE request."""
        return await self.request("DELETE", url, **kwargs)
    
    def _log_request(self, method: str, url: str, status_code: int, elapsed: float) -> None:
        """Log a request with colorized status code."""
        # Color based on status code
        if status_code < 300:
            status_style = "green"
        elif status_code < 400:
            status_style = "yellow"
        elif status_code < 500:
            status_style = "red"
        else:
            status_style = "bold red"
        
        logger.debug(f"{method} {url} -> {status_code} ({elapsed:.2f}s)")
