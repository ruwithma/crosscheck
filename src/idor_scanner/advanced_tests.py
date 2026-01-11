"""
Advanced IDOR Tests for CrossCheck Scanner.

Implements additional vulnerability detection techniques:
- Mass Assignment Detection
- API Versioning Bypass
- Parameter Pollution
"""

import logging
import re
import copy
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from .models import Endpoint, HttpMethod, Vulnerability, Severity, Evidence
from .comparator import ResponseComparator

logger = logging.getLogger(__name__)


class MassAssignmentTester:
    """
    Tests for Mass Assignment vulnerabilities.
    
    Attempts to add privileged fields to requests to see if they
    are accepted and reflected in the response.
    """
    
    # Common privileged fields to inject
    PRIVILEGED_FIELDS = [
        ('role', 'admin'),
        ('is_admin', True),
        ('admin', True),
        ('isAdmin', True),
        ('is_superuser', True),
        ('privilege', 'admin'),
        ('user_type', 'admin'),
        ('userType', 'admin'),
        ('permissions', ['admin', 'write', 'delete']),
        ('verified', True),
        ('active', True),
        ('approved', True),
        ('balance', 999999),
        ('credit', 999999),
        ('price', 0),
        ('discount', 100),
    ]
    
    def __init__(self, http_client, comparator: ResponseComparator):
        self.http_client = http_client
        self.comparator = comparator
    
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        session_headers: Dict[str, str],
        base_url: str,
        original_body: Optional[Dict] = None
    ) -> List[Tuple[str, Any, bool]]:
        """
        Test an endpoint for mass assignment vulnerabilities.
        
        Args:
            endpoint: Endpoint to test
            session_headers: Authentication headers
            base_url: Base URL of the API
            original_body: Original request body (if any)
            
        Returns:
            List of (field_name, injected_value, was_reflected) tuples
        """
        results = []
        
        # Only test POST, PUT, PATCH methods
        if endpoint.method not in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH]:
            return results
        
        url = endpoint.url_for(base_url)
        body = original_body or endpoint.body_template or {}
        
        for field_name, field_value in self.PRIVILEGED_FIELDS:
            try:
                # Skip if field already exists
                if field_name in body:
                    continue
                
                # Add privileged field
                test_body = copy.deepcopy(body)
                test_body[field_name] = field_value
                
                response = await self.http_client.request(
                    endpoint.method.value,
                    url,
                    json=test_body,
                    headers=session_headers
                )
                
                if response.status_code in [200, 201]:
                    # Check if field was reflected in response
                    try:
                        resp_data = response.json()
                        reflected = self._check_field_reflected(resp_data, field_name, field_value)
                        if reflected:
                            logger.warning(f"Mass Assignment: {field_name}={field_value} was reflected!")
                            results.append((field_name, field_value, True))
                    except:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error testing field {field_name}: {e}")
        
        return results
    
    def _check_field_reflected(self, response: Any, field_name: str, expected_value: Any) -> bool:
        """Check if a field was reflected in the response."""
        if isinstance(response, dict):
            if field_name in response:
                return response[field_name] == expected_value
            # Recursive check
            for value in response.values():
                if self._check_field_reflected(value, field_name, expected_value):
                    return True
        elif isinstance(response, list):
            for item in response:
                if self._check_field_reflected(item, field_name, expected_value):
                    return True
        return False


class APIVersioningTester:
    """
    Tests for API versioning bypass vulnerabilities.
    
    Checks if older API versions have weaker access controls.
    """
    
    # Common version patterns
    VERSION_PATTERNS = [
        (r'/v(\d+)/', '/v{}/'),           # /v1/, /v2/
        (r'/api/v(\d+)/', '/api/v{}/'),   # /api/v1/
        (r'/api(\d+)/', '/api{}/'),       # /api1/
        (r'version=(\d+)', 'version={}'), # ?version=1
    ]
    
    def __init__(self, http_client, comparator: ResponseComparator):
        self.http_client = http_client
        self.comparator = comparator
    
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        session_headers: Dict[str, str],
        base_url: str,
        blocked_response: httpx.Response
    ) -> List[Dict]:
        """
        Test older API versions for weaker access control.
        
        Args:
            endpoint: Endpoint that was blocked
            session_headers: Attacker's session headers
            base_url: Base URL
            blocked_response: The 403/401 response from current version
            
        Returns:
            List of successful bypass results
        """
        results = []
        url = endpoint.url_for(base_url)
        
        for pattern, replacement in self.VERSION_PATTERNS:
            match = re.search(pattern, url)
            if not match:
                continue
            
            current_version = int(match.group(1))
            
            # Try older versions
            for older_version in range(current_version - 1, 0, -1):
                try:
                    old_url = re.sub(pattern, replacement.format(older_version), url)
                    
                    response = await self.http_client.request(
                        endpoint.method.value,
                        old_url,
                        headers=session_headers
                    )
                    
                    if response.status_code == 200:
                        logger.warning(f"API Version Bypass: {old_url} returned 200!")
                        results.append({
                            'original_url': url,
                            'bypass_url': old_url,
                            'original_version': current_version,
                            'bypass_version': older_version,
                            'response_status': response.status_code
                        })
                        break  # Found bypass, no need to try older versions
                        
                except Exception as e:
                    logger.debug(f"Error testing version {older_version}: {e}")
        
        return results


class ParameterPollutionTester:
    """
    Tests for HTTP Parameter Pollution vulnerabilities.
    
    Tests if duplicate parameters or array notation can bypass access controls.
    """
    
    def __init__(self, http_client):
        self.http_client = http_client
    
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        session_headers: Dict[str, str],
        base_url: str,
        attacker_id: str,
        victim_id: str
    ) -> List[Dict]:
        """
        Test parameter pollution techniques.
        
        Args:
            endpoint: Endpoint to test
            session_headers: Attacker's session headers
            base_url: Base URL
            attacker_id: Attacker's user ID
            victim_id: Victim's user ID
            
        Returns:
            List of successful pollution results
        """
        results = []
        url = endpoint.url_for(base_url)
        parsed = urlparse(url)
        
        # Find ID parameters in the URL
        if not endpoint.resource_ids:
            return results
        
        # Pollution techniques
        techniques = [
            # Technique 1: Duplicate parameter (attacker first, victim second)
            lambda p, v: f"{p}={attacker_id}&{p}={v}",
            
            # Technique 2: Duplicate parameter (victim first, attacker second)
            lambda p, v: f"{p}={v}&{p}={attacker_id}",
            
            # Technique 3: Array notation
            lambda p, v: f"{p}[]={attacker_id}&{p}[]={v}",
            
            # Technique 4: Comma-separated
            lambda p, v: f"{p}={attacker_id},{v}",
            
            # Technique 5: JSON array in query
            lambda p, v: f"{p}=[{attacker_id},{v}]",
        ]
        
        for resource_id in endpoint.resource_ids:
            param_name = 'id'  # Default
            
            # Determine the parameter name
            if '?' in url and '=' in url:
                # It's in query string
                query_params = parse_qs(parsed.query)
                for key in query_params:
                    if resource_id.value in query_params[key]:
                        param_name = key
                        break
            
            for i, technique in enumerate(techniques):
                try:
                    # Build polluted query
                    polluted_query = technique(param_name, victim_id)
                    
                    # Reconstruct URL
                    new_parsed = parsed._replace(query=polluted_query)
                    polluted_url = urlunparse(new_parsed)
                    
                    response = await self.http_client.request(
                        endpoint.method.value,
                        polluted_url,
                        headers=session_headers
                    )
                    
                    if response.status_code == 200:
                        # Check if we got victim's data
                        try:
                            data = response.json()
                            if victim_id in str(data):
                                logger.warning(f"Parameter Pollution Success: Technique {i+1}")
                                results.append({
                                    'technique': i + 1,
                                    'polluted_url': polluted_url,
                                    'response_status': response.status_code,
                                    'victim_data_leaked': True
                                })
                        except:
                            pass
                            
                except Exception as e:
                    logger.debug(f"Error in pollution technique {i+1}: {e}")
        
        return results
