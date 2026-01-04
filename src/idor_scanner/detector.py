"""
IDOR Detection Engine for the Scanner.

Core testing logic for detecting Broken Access Control vulnerabilities.
Tests for horizontal and vertical privilege escalation, method tampering, etc.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from .comparator import ComparisonResult, ResponseComparator
from .discovery import EndpointDiscovery
from .http_client import HTTPClient
from .models import (
    Endpoint,
    EndpointResult,
    Evidence,
    HttpMethod,
    ScanConfig,
    ScanResult,
    Session,
    Severity,
    Vulnerability,
)
from .session import SessionManager

logger = logging.getLogger(__name__)


class IDORDetector:
    """
    Core IDOR detection engine.
    
    Tests API endpoints for:
    - Horizontal privilege escalation (user A accessing user B's resources)
    - Vertical privilege escalation (user accessing admin resources)
    - HTTP method tampering (GET blocked but POST works)
    - Parameter pollution
    """
    
    def __init__(
        self,
        http_client: HTTPClient,
        session_manager: SessionManager,
        config: ScanConfig,
    ):
        self.http_client = http_client
        self.session_manager = session_manager
        self.config = config
        self.comparator = ResponseComparator()
        
        # Results
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoint_results: List[EndpointResult] = []
    
    async def scan(
        self,
        discovery: EndpointDiscovery,
        sessions: Dict[str, Session],
    ) -> ScanResult:
        """
        Run a complete IDOR scan.
        
        Args:
            discovery: EndpointDiscovery with discovered endpoints
            sessions: Dict of user_id -> Session for testing
            
        Returns:
            ScanResult with all findings
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.now()
        
        logger.info(f"Starting IDOR scan {scan_id}")
        
        # Get testable endpoints (those with resource IDs)
        endpoints = discovery.get_testable_endpoints()
        logger.info(f"Found {len(endpoints)} testable endpoints")
        
        if not endpoints:
            logger.warning("No testable endpoints found!")
            return ScanResult(
                scan_id=scan_id,
                target=self.config.target,
                start_time=start_time,
                end_time=datetime.now(),
                config=self.config.model_dump(),
                status="completed",
            )
        
        # Get session list
        session_list = list(sessions.values())
        if len(session_list) < 2:
            logger.error("At least 2 sessions required for IDOR testing")
            raise ValueError("IDOR testing requires at least 2 authenticated sessions")
        
        # Primary victim and attacker sessions
        victim_session = session_list[0]
        attacker_session = session_list[1]
        
        # Optional admin session
        admin_session = next(
            (s for s in session_list if s.role == "admin"),
            None
        )
        
        # Test each endpoint
        for endpoint in endpoints:
            try:
                result = await self.test_endpoint(
                    endpoint,
                    victim_session,
                    attacker_session,
                    admin_session,
                )
                self.endpoint_results.append(result)
                
                if result.vulnerabilities:
                    self.vulnerabilities.extend(result.vulnerabilities)
                    logger.warning(
                        f"[VULN] {len(result.vulnerabilities)} vulnerabilities in "
                        f"{endpoint.method.value} {endpoint.path}"
                    )
                    
            except Exception as e:
                logger.error(f"Error testing endpoint {endpoint.path}: {e}")
                self.endpoint_results.append(EndpointResult(
                    endpoint=endpoint,
                    tested=False,
                    error=str(e),
                ))
        
        # Build result
        result = ScanResult(
            scan_id=scan_id,
            target=self.config.target,
            start_time=start_time,
            end_time=datetime.now(),
            config=self.config.model_dump(),
            endpoints_discovered=len(discovery.discovered_endpoints),
            endpoints_scanned=len(endpoints),
            endpoint_results=self.endpoint_results,
            vulnerabilities=self.vulnerabilities,
            status="completed",
        )
        
        logger.info(
            f"Scan complete: {len(self.vulnerabilities)} vulnerabilities found "
            f"in {result.duration:.1f}s"
        )
        
        return result
    
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        victim_session: Session,
        attacker_session: Session,
        admin_session: Optional[Session] = None,
    ) -> EndpointResult:
        """
        Test a single endpoint for IDOR vulnerabilities.
        
        Args:
            endpoint: The endpoint to test
            victim_session: Session of the "victim" user
            attacker_session: Session of the "attacker" user
            admin_session: Optional admin session for vertical testing
            
        Returns:
            EndpointResult with any findings
        """
        vulnerabilities: List[Vulnerability] = []
        
        logger.debug(f"Testing {endpoint.method.value} {endpoint.path}")
        
        # Step 1: Get baseline (victim accessing their own resource)
        baseline = await self._get_baseline(endpoint, victim_session)
        
        if baseline is None:
            logger.debug(f"Could not establish baseline for {endpoint.path}")
            return EndpointResult(
                endpoint=endpoint,
                tested=False,
                error="Could not establish baseline",
            )
        
        # Step 2: Test horizontal escalation
        horizontal_vuln = await self._test_horizontal(
            endpoint,
            baseline,
            victim_session,
            attacker_session,
        )
        if horizontal_vuln:
            vulnerabilities.append(horizontal_vuln)
        
        # Step 3: Test vertical escalation (if admin session available)
        if admin_session:
            vertical_vuln = await self._test_vertical(
                endpoint,
                victim_session,
                admin_session,
            )
            if vertical_vuln:
                vulnerabilities.append(vertical_vuln)
        
        # Step 4: Test method tampering
        method_vulns = await self._test_method_tampering(
            endpoint,
            baseline,
            victim_session,
            attacker_session,
        )
        vulnerabilities.extend(method_vulns)
        
        return EndpointResult(
            endpoint=endpoint,
            tested=True,
            vulnerable=len(vulnerabilities) > 0,
            vulnerabilities=vulnerabilities,
        )
    
    async def _get_baseline(
        self,
        endpoint: Endpoint,
        session: Session,
    ) -> Optional[httpx.Response]:
        """Get baseline response (authorized access)."""
        
        # Use the first resource ID from the endpoint
        url = endpoint.url_for(self.config.target)
        
        try:
            response = await self.session_manager.make_request(
                session,
                endpoint.method.value,
                url,
            )
            
            if response.status_code == 200:
                return response
            
            logger.debug(f"Baseline returned {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting baseline: {e}")
            return None
    
    async def _test_horizontal(
        self,
        endpoint: Endpoint,
        baseline: httpx.Response,
        victim_session: Session,
        attacker_session: Session,
    ) -> Optional[Vulnerability]:
        """
        Test horizontal privilege escalation.
        
        Attacker (user B) tries to access victim's (user A) resource.
        """
        url = endpoint.url_for(self.config.target)
        
        try:
            # Attacker tries to access victim's resource
            response = await self.session_manager.make_request(
                attacker_session,
                endpoint.method.value,
                url,
            )
            
            # Compare responses
            comparison = self.comparator.compare(baseline, response, "horizontal")
            
            if comparison and comparison.is_vulnerable:
                return self._create_vulnerability(
                    endpoint=endpoint,
                    comparison=comparison,
                    victim=victim_session,
                    attacker=attacker_session,
                    baseline=baseline,
                    attack_response=response,
                    vuln_type="Horizontal Privilege Escalation",
                )
            
            # If blocked (401/403), try bypasses
            elif response.status_code in [401, 403]:
                bypass_vuln = await self._attempt_bypass(
                    endpoint,
                    url,
                    baseline,
                    victim_session,
                    attacker_session,
                    "horizontal"
                )
                if bypass_vuln:
                    return bypass_vuln
                
        except Exception as e:
            logger.error(f"Error in horizontal test: {e}")
        
        return None

    async def _attempt_bypass(
        self,
        endpoint: Endpoint,
        url: str,
        baseline: httpx.Response,
        victim_session: Session,
        attacker_session: Session,
        check_type: str
    ) -> Optional[Vulnerability]:
        """Attempt to bypass 403/401 restrictions."""
        
        # Bypass techniques
        bypasses = [
            # Header manipulation
            {"headers": {"X-Original-URL": endpoint.path}},
            {"headers": {"X-Rewrite-URL": endpoint.path}},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
            {"headers": {"X-Forwarded-For": "127.0.0.1"}},
            
            # Request method tampering (if original was GET)
            # {"method": "POST", "headers": {"X-HTTP-Method-Override": "GET"}},
            
            # URL manipulation (simple ones)
            # /api/users/1 -> /api/users/./1
            {"url_transform": lambda u: u.replace(endpoint.path, endpoint.path.replace('/', '/./'))},
            # /api/users/1 -> /api/users/%20/1
            {"url_transform": lambda u: u.replace(endpoint.path, endpoint.path.replace('/', '/%20/'))},
        ]
        
        for technique in bypasses:
            try:
                # Prepare request options
                req_url = url
                if "url_transform" in technique:
                    req_url = technique["url_transform"](url)
                
                req_headers = technique.get("headers", {})
                
                # Make request
                response = await self.session_manager.make_request(
                    attacker_session,
                    endpoint.method.value,
                    req_url,
                    headers=req_headers
                )
                
                # Only analyze if we got a different status code than the block
                if response.status_code not in [401, 403]:
                    comparison = self.comparator.compare(baseline, response, check_type)
                    
                    if comparison and comparison.is_vulnerable:
                        technique_name = ", ".join(f"{k}={v}" for k,v in req_headers.items()) or "URL Manipulation"
                        comparison.description += f" (Bypassed 403 via {technique_name})"
                        
                        return self._create_vulnerability(
                            endpoint=endpoint,
                            comparison=comparison,
                            victim=victim_session,
                            attacker=attacker_session,
                            baseline=baseline,
                            attack_response=response,
                            vuln_type=f"Bypass {check_type.capitalize()} Escalation",
                            bypass_headers=req_headers, # Custom arg to store bypass info
                            attack_url=req_url,
                        )
            except Exception:
                continue
                
        return None
    
    async def _test_vertical(
        self,
        endpoint: Endpoint,
        user_session: Session,
        admin_session: Session,
    ) -> Optional[Vulnerability]:
        """
        Test vertical privilege escalation.
        
        Regular user tries to access admin-only resources.
        """
        # First, get admin baseline
        url = endpoint.url_for(self.config.target)
        
        try:
            admin_response = await self.session_manager.make_request(
                admin_session,
                endpoint.method.value,
                url,
            )
            
            if admin_response.status_code != 200:
                return None
            
            # Now try with regular user
            user_response = await self.session_manager.make_request(
                user_session,
                endpoint.method.value,
                url,
            )
            
            # Compare responses
            comparison = self.comparator.compare(admin_response, user_response, "vertical")
            
            if comparison and comparison.is_vulnerable:
                return self._create_vulnerability(
                    endpoint=endpoint,
                    comparison=comparison,
                    victim=admin_session,
                    attacker=user_session,
                    baseline=admin_response,
                    attack_response=user_response,
                    vuln_type="Vertical Privilege Escalation",
                )
                
        except Exception as e:
            logger.error(f"Error in vertical test: {e}")
        
        return None
    
    async def _test_method_tampering(
        self,
        endpoint: Endpoint,
        baseline: httpx.Response,
        victim_session: Session,
        attacker_session: Session,
    ) -> List[Vulnerability]:
        """
        Test HTTP method tampering.
        
        If GET is blocked, try POST, PUT, PATCH, DELETE.
        """
        vulnerabilities = []
        
        # Methods to try
        methods_to_test = [
            HttpMethod.POST,
            HttpMethod.PUT,
            HttpMethod.PATCH,
            HttpMethod.DELETE,
        ]
        
        # Remove the original method
        methods_to_test = [m for m in methods_to_test if m != endpoint.method]
        
        url = endpoint.url_for(self.config.target)
        
        for method in methods_to_test:
            try:
                # First check if victim can use this method
                victim_response = await self.session_manager.make_request(
                    victim_session,
                    method.value,
                    url,
                )
                
                if victim_response.status_code not in [200, 201, 204]:
                    continue  # Method not supported
                
                # Now try with attacker
                attacker_response = await self.session_manager.make_request(
                    attacker_session,
                    method.value,
                    url,
                )
                
                comparison = self.comparator.compare(
                    victim_response, 
                    attacker_response, 
                    "method_tampering"
                )
                
                if comparison and comparison.is_vulnerable:
                    vuln = self._create_vulnerability(
                        endpoint=Endpoint(
                            path=endpoint.path,
                            method=method,
                            resource_ids=endpoint.resource_ids,
                        ),
                        comparison=comparison,
                        victim=victim_session,
                        attacker=attacker_session,
                        baseline=victim_response,
                        attack_response=attacker_response,
                        vuln_type="HTTP Method Tampering",
                    )
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                logger.debug(f"Error testing method {method.value}: {e}")
        
        return vulnerabilities
    
    def _create_vulnerability(
        self,
        endpoint: Endpoint,
        comparison: ComparisonResult,
        victim: Session,
        attacker: Session,
        baseline: httpx.Response,
        attack_response: httpx.Response,
        vuln_type: str,
        bypass_headers: Optional[Dict[str, str]] = None,
        attack_url: Optional[str] = None,
    ) -> Vulnerability:
        """Create a Vulnerability object from a comparison result."""
        
        target_url = attack_url or endpoint.url_for(self.config.target)
        
        # Build evidence
        evidence = Evidence(
            baseline_request={
                "method": endpoint.method.value,
                "url": endpoint.url_for(self.config.target),
                "user": victim.user_id,
            },
            baseline_response={
                "status_code": baseline.status_code,
                "body_preview": baseline.text[:500] if baseline.text else None,
            },
            attack_request={
                "method": endpoint.method.value,
                "url": target_url,
                "user": attacker.user_id,
                "headers": bypass_headers or {}, 
            },
            attack_response={
                "status_code": attack_response.status_code,
                "body_preview": attack_response.text[:500] if attack_response.text else None,
            },
            comparison_details=comparison.evidence,
            sensitive_fields_exposed=comparison.evidence.get("sensitive_fields_exposed", []),
        )
        
        # Determine impact
        impact = self._assess_impact(comparison, endpoint)
        
        # Remediation
        remediation = self._generate_remediation(endpoint)
        
        return Vulnerability(
            id=str(uuid.uuid4())[:8],
            title=f"{vuln_type} in {endpoint.method.value} {endpoint.path}",
            severity=comparison.severity,
            vuln_type=comparison.vuln_type,
            endpoint=endpoint.path,
            method=endpoint.method,
            description=comparison.description,
            impact=impact,
            evidence=evidence,
            victim_user=victim.user_id,
            attacker_user=attacker.user_id,
            remediation=remediation,
        )
    
    def _assess_impact(self, comparison: ComparisonResult, endpoint: Endpoint) -> str:
        """Assess the business impact of the vulnerability."""
        
        sensitive = comparison.evidence.get("sensitive_fields_exposed", [])
        
        if any("password" in s.lower() or "token" in s.lower() for s in sensitive):
            return (
                "CRITICAL: Authentication credentials exposed. "
                "Attackers can take over user accounts."
            )
        
        if any("credit_card" in s.lower() or "ssn" in s.lower() for s in sensitive):
            return (
                "CRITICAL: Financial or PII data exposed. "
                "Regulatory violations (PCI-DSS, GDPR) likely."
            )
        
        if "user" in endpoint.path.lower():
            return (
                "HIGH: User data can be accessed by other users. "
                "All user profiles may be enumerable."
            )
        
        if "order" in endpoint.path.lower() or "payment" in endpoint.path.lower():
            return (
                "HIGH: Transaction data exposed. "
                "Financial data and order history accessible."
            )
        
        return (
            "MEDIUM: Unauthorized data access possible. "
            "Resource data can be accessed by other users."
        )
    
    def _generate_remediation(self, endpoint: Endpoint) -> str:
        """Generate remediation code example."""
        
        return f'''# Add authorization check before returning data
@app.route('{endpoint.path}')
@login_required
def get_resource(resource_id):
    resource = Resource.query.get(resource_id)
    
    if resource is None:
        return {{"error": "Not found"}}, 404
    
    # Authorization check - ensure user owns the resource
    if resource.user_id != current_user.id:
        return {{"error": "Unauthorized"}}, 403
    
    return resource.to_json()
'''
