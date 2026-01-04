"""
Endpoint Discovery for the IDOR Scanner.

Discovers API endpoints through various methods:
- OpenAPI/Swagger parsing
- API crawling
- Manual import
- ID extraction from URLs
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from .http_client import HTTPClient
from .models import Endpoint, HttpMethod, IDType, ResourceID

logger = logging.getLogger(__name__)


# Patterns for extracting resource IDs from URLs
ID_PATTERNS: List[Tuple[str, IDType]] = [
    (r'/(\d+)(?:/|$|\?)', IDType.NUMERIC),                    # /users/123
    (r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)', IDType.UUID),  # UUID v4
    (r'/([A-Za-z0-9_-]{8,})(?:/|$|\?)', IDType.ALPHANUMERIC), # /posts/abc123xyz
    (r'\?.*?id=(\d+)', IDType.QUERY_NUMERIC),                  # ?id=123
    (r'\?.*?id=([^&]+)', IDType.QUERY_STRING),                 # ?id=abc
    # Composite ID patterns (e.g., Zara: user_id_session_id)
    (r'/(\d+_\d+)(?:/|$|\?)', IDType.ALPHANUMERIC),           # /wishlist/123_456
    (r'/([A-Za-z0-9]+_[A-Za-z0-9]+)(?:/|$|\?)', IDType.ALPHANUMERIC),  # /detail/abc_def
]

# Common API path patterns
COMMON_API_PATTERNS = [
    '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
    '/itxrest/', '/user/', '/session/', '/account/',
]

# AJAX query parameter variants
AJAX_VARIANTS = ['?ajax=true', '?format=json', '?_format=json']

# Common resource endpoints
COMMON_ENDPOINTS = [
    '/api/users/{id}',
    '/api/users/{id}/profile',
    '/api/accounts/{id}',
    '/api/orders/{id}',
    '/api/orders/{id}/items',
    '/api/products/{id}',
    '/api/documents/{id}',
    '/api/documents/{id}/download',
    '/api/messages/{id}',
    '/api/comments/{id}',
    '/api/posts/{id}',
]


class DiscoveryError(Exception):
    """Error during endpoint discovery."""
    pass


class EndpointDiscovery:
    """
    Discovers API endpoints from various sources.
    
    Features:
    - Parse OpenAPI/Swagger specifications
    - Crawl API from base URL
    - Extract resource IDs from URLs
    - Manual endpoint import
    - Endpoint categorization
    """
    
    def __init__(self, http_client: HTTPClient, base_url: str):
        self.http_client = http_client
        self.base_url = base_url.rstrip('/')
        self.discovered_endpoints: List[Endpoint] = []
        self.visited_urls: Set[str] = set()
    
    async def discover_all(
        self,
        openapi_path: Optional[str] = None,
        endpoints_file: Optional[str] = None,
        crawl: bool = True,
        max_depth: int = 3,
    ) -> List[Endpoint]:
        """
        Discover endpoints using all available methods.
        
        Args:
            openapi_path: Path/URL to OpenAPI spec (optional)
            endpoints_file: Path to manual endpoints file (optional)
            crawl: Whether to crawl the API
            max_depth: Maximum crawl depth
            
        Returns:
            List of discovered endpoints
        """
        endpoints: List[Endpoint] = []
        
        # Method 1: Parse OpenAPI/Swagger
        if openapi_path:
            logger.info(f"Parsing OpenAPI spec: {openapi_path}")
            openapi_endpoints = await self.parse_openapi(openapi_path)
            endpoints.extend(openapi_endpoints)
            logger.info(f"Found {len(openapi_endpoints)} endpoints from OpenAPI")
        
        # Method 2: Try common OpenAPI paths
        if not openapi_path:
            common_paths = [
                '/swagger.json',
                '/openapi.json',
                '/api-docs',
                '/swagger/v1/swagger.json',
                '/v1/swagger.json',
                '/api/swagger.json',
            ]
            for path in common_paths:
                try:
                    spec_url = f"{self.base_url}{path}"
                    openapi_endpoints = await self.parse_openapi(spec_url)
                    if openapi_endpoints:
                        endpoints.extend(openapi_endpoints)
                        logger.info(f"Found OpenAPI spec at {path}")
                        break
                except Exception:
                    continue
        
        # Method 3: Load from file
        if endpoints_file:
            logger.info(f"Loading endpoints from file: {endpoints_file}")
            file_endpoints = self.load_from_file(endpoints_file)
            endpoints.extend(file_endpoints)
            logger.info(f"Loaded {len(file_endpoints)} endpoints from file")
        
        # Method 4: Crawl API
        if crawl:
            logger.info(f"Crawling API from: {self.base_url}")
            crawled = await self.crawl_api(max_depth=max_depth)
            endpoints.extend(crawled)
            logger.info(f"Discovered {len(crawled)} endpoints via crawling")
        
        # Deduplicate
        unique_endpoints = self._deduplicate_endpoints(endpoints)
        self.discovered_endpoints = unique_endpoints
        
        logger.info(f"Total unique endpoints discovered: {len(unique_endpoints)}")
        return unique_endpoints
    
    async def parse_openapi(self, spec_path: str) -> List[Endpoint]:
        """
        Parse an OpenAPI/Swagger specification.
        
        Args:
            spec_path: URL or file path to the spec
            
        Returns:
            List of endpoints from the spec
        """
        endpoints = []
        
        try:
            # Fetch or load spec
            if spec_path.startswith(('http://', 'https://')):
                response = await self.http_client.get(spec_path)
                if response.status_code != 200:
                    logger.warning(f"Failed to fetch OpenAPI spec: {response.status_code}")
                    return []
                spec = response.json()
            else:
                import json
                with open(spec_path, 'r') as f:
                    spec = json.load(f)
            
            # Parse paths
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
                        continue
                    
                    # Extract parameters
                    parameters = {}
                    for param in details.get('parameters', []):
                        parameters[param.get('name')] = {
                            'in': param.get('in'),
                            'required': param.get('required', False),
                            'type': param.get('schema', {}).get('type', 'string'),
                        }
                    
                    # Check auth requirement
                    auth_required = bool(details.get('security', spec.get('security')))
                    
                    # Extract resource IDs
                    resource_ids = self.extract_ids_from_path(path)
                    
                    endpoint = Endpoint(
                        path=path,
                        method=HttpMethod(method.upper()),
                        parameters=parameters,
                        resource_ids=resource_ids,
                        auth_required=auth_required,
                        description=details.get('summary', details.get('description')),
                    )
                    endpoints.append(endpoint)
            
        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {e}")
        
        return endpoints
    
    async def crawl_api(self, max_depth: int = 3) -> List[Endpoint]:
        """
        Crawl the API to discover endpoints.
        
        Args:
            max_depth: Maximum depth to crawl
            
        Returns:
            List of discovered endpoints
        """
        endpoints = []
        queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        
        while queue:
            url, depth = queue.pop(0)
            
            if depth > max_depth:
                continue
            
            if url in self.visited_urls:
                continue
            
            self.visited_urls.add(url)
            
            try:
                response = await self.http_client.get(url)
                
                if response.status_code == 200:
                    # Extract API endpoints from response
                    extracted = await self._extract_endpoints_from_response(
                        response, url, depth
                    )
                    endpoints.extend(extracted)
                    
                    # Extract links for further crawling
                    links = self._extract_links(response, url)
                    for link in links:
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))
                            
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
        
        return endpoints
    
    async def _extract_endpoints_from_response(
        self, 
        response: httpx.Response, 
        url: str,
        depth: int
    ) -> List[Endpoint]:
        """Extract API endpoints from a response."""
        endpoints = []
        
        try:
            data = response.json()
            
            # Look for API-like patterns in the response
            if isinstance(data, dict):
                # Check for embedded URLs
                self._find_urls_in_json(data, endpoints)
            
        except Exception:
            # Not JSON, try HTML parsing
            pass
        
        # Create endpoint for this URL if it looks like an API endpoint
        if any(pattern in url for pattern in COMMON_API_PATTERNS):
            resource_ids = self.extract_ids_from_url(url)
            
            endpoint = Endpoint(
                path=urlparse(url).path,
                method=HttpMethod.GET,
                resource_ids=resource_ids,
            )
            
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        
        return endpoints
    
    def _find_urls_in_json(self, data: Any, endpoints: List[Endpoint], prefix: str = "") -> None:
        """Recursively find URL-like strings in JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str) and ('/' in value or 'http' in value):
                    # Check if it looks like an API endpoint
                    if any(pattern in value for pattern in ['/api/', '/v1/', '/v2/']):
                        path = value if value.startswith('/') else urlparse(value).path
                        if path:
                            resource_ids = self.extract_ids_from_path(path)
                            endpoint = Endpoint(
                                path=path,
                                method=HttpMethod.GET,
                                resource_ids=resource_ids,
                            )
                            endpoints.append(endpoint)
                else:
                    self._find_urls_in_json(value, endpoints, f"{prefix}.{key}")
                    
        elif isinstance(data, list):
            for item in data:
                self._find_urls_in_json(item, endpoints, prefix)
    
    def _extract_links(self, response: httpx.Response, base_url: str) -> Set[str]:
        """Extract links from a response for further crawling."""
        links: Set[str] = set()
        
        try:
            data = response.json()
            self._find_links_in_json(data, links, base_url)
        except Exception:
            pass
        
        return links
    
    def _find_links_in_json(self, data: Any, links: Set[str], base_url: str) -> None:
        """Recursively find links in JSON data."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    if value.startswith('http'):
                        # Same domain only
                        if urlparse(value).netloc == urlparse(base_url).netloc:
                            links.add(value)
                    elif value.startswith('/'):
                        links.add(urljoin(base_url, value))
                else:
                    self._find_links_in_json(value, links, base_url)
                    
        elif isinstance(data, list):
            for item in data:
                self._find_links_in_json(item, links, base_url)
    
    def extract_ids_from_url(self, url: str) -> List[ResourceID]:
        """Extract resource IDs from a full URL."""
        return self.extract_ids_from_path(urlparse(url).path)
    
    def extract_ids_from_path(self, path: str) -> List[ResourceID]:
        """Extract resource IDs from a URL path."""
        resource_ids = []
        
        for pattern, id_type in ID_PATTERNS:
            matches = re.finditer(pattern, path, re.IGNORECASE)
            for i, match in enumerate(matches):
                resource_ids.append(ResourceID(
                    value=match.group(1),
                    id_type=id_type,
                    position=match.start(),
                ))
        
        # Also check for path parameters like {id}
        param_pattern = r'\{(\w+)\}'
        matches = re.finditer(param_pattern, path)
        for match in matches:
            # Don't add if already exists
            if not any(rid.value == match.group(1) for rid in resource_ids):
                resource_ids.append(ResourceID(
                    value=match.group(1),
                    id_type=IDType.ALPHANUMERIC,
                    position=match.start(),
                ))
        
        return resource_ids
    
    def load_from_file(self, filepath: str) -> List[Endpoint]:
        """
        Load endpoints from a text file.
        
        Format:
            GET /api/users/{id}
            POST /api/orders
            PUT /api/accounts/{id}/settings
        """
        endpoints = []
        
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        method, path = parts
                        resource_ids = self.extract_ids_from_path(path)
                        
                        try:
                            http_method = HttpMethod(method.upper())
                        except ValueError:
                            http_method = HttpMethod.GET
                        
                        endpoint = Endpoint(
                            path=path,
                            method=http_method,
                            resource_ids=resource_ids,
                        )
                        endpoints.append(endpoint)
                        
        except FileNotFoundError:
            logger.error(f"Endpoints file not found: {filepath}")
        except Exception as e:
            logger.error(f"Error reading endpoints file: {e}")
        
        return endpoints
    
    def _deduplicate_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Remove duplicate endpoints."""
        seen = set()
        unique = []
        
        for ep in endpoints:
            key = (ep.method, ep.path)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        
        return unique
    
    def get_testable_endpoints(self) -> List[Endpoint]:
        """Get endpoints that have resource IDs and can be tested for IDOR."""
        return [ep for ep in self.discovered_endpoints if ep.resource_ids]
