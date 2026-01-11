"""
Data models for the IDOR Scanner.

Pydantic models for configuration, endpoints, sessions, 
vulnerabilities, and scan results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class AuthType(str, Enum):
    """Supported authentication types."""
    BEARER = "bearer"
    BASIC = "basic"
    COOKIE = "cookie"
    API_KEY = "api_key"
    NONE = "none"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class HttpMethod(str, Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class IDType(str, Enum):
    """Types of resource identifiers."""
    NUMERIC = "numeric"
    UUID = "uuid"
    ALPHANUMERIC = "alphanumeric"
    QUERY_NUMERIC = "query_numeric"
    QUERY_STRING = "query_string"


# --- Configuration Models ---

class UserCredentials(BaseModel):
    """User credentials for authentication."""
    username: str
    password: str
    role: str = "user"
    auth_type: AuthType = AuthType.BEARER
    auth_endpoint: Optional[str] = None
    extra_headers: Dict[str, str] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Configuration for a scan."""
    target: str  # Base URL of the API
    users: List[UserCredentials] = Field(min_length=2)
    timeout: int = Field(default=30, ge=1, le=300)
    rate_limit: int = Field(default=10, ge=1, le=100)  # requests per second
    max_depth: int = Field(default=3, ge=1, le=10)  # crawl depth
    verify_ssl: bool = True
    follow_redirects: bool = True
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    exclude_patterns: List[str] = Field(default_factory=list)
    proxy: Optional[str] = None


# --- Endpoint Models ---

class ResourceID(BaseModel):
    """A resource identifier extracted from a URL."""
    value: str
    id_type: IDType
    position: int  # Position in URL path


class Endpoint(BaseModel):
    """An API endpoint discovered during scanning."""
    path: str
    method: HttpMethod = HttpMethod.GET
    parameters: Dict[str, Any] = Field(default_factory=dict)
    resource_ids: List[ResourceID] = Field(default_factory=list)
    body_template: Optional[Dict[str, Any]] = None
    auth_required: bool = True
    description: Optional[str] = None
    
    def url_for(self, base_url: str, id_value: Optional[str] = None) -> str:
        """Generate full URL, optionally replacing the resource ID."""
        path = self.path
        if id_value and self.resource_ids:
            # Replace the first resource ID with the provided value
            first_id = self.resource_ids[0]
            if first_id.position == -1: # Reserved for body
                return f"{base_url.rstrip('/')}{path}"
            
            path = path.replace(f"{{{first_id.value}}}", id_value)
            path = path.replace(first_id.value, id_value)
        return f"{base_url.rstrip('/')}{path}"

    def body_for(self, id_value: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Generate request body, optionally replacing the resource ID."""
        if not self.body_template:
            return None
            
        if not id_value:
            return self.body_template.copy()
            
        # Deep copy and replace
        import json
        body_str = json.dumps(self.body_template)
        
        if self.resource_ids:
            first_id = self.resource_ids[0]
            # If the ID is meant for the body (we can mark position -1 or just try replace)
            body_str = body_str.replace(f"{{{first_id.value}}}", id_value)
            body_str = body_str.replace(first_id.value, id_value)
            
        return json.loads(body_str)


# --- Session Models ---

@dataclass
class Session:
    """An authenticated user session."""
    user_id: str
    role: str
    credentials: UserCredentials
    auth_type: AuthType
    
    # Authentication data
    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        """Check if the session token has expired."""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests."""
        auth_headers = dict(self.headers)
        
        if self.auth_type == AuthType.BEARER and self.token:
            auth_headers["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == AuthType.BASIC and self.token:
            auth_headers["Authorization"] = f"Basic {self.token}"
        elif self.auth_type == AuthType.API_KEY and self.token:
            auth_headers["X-API-Key"] = self.token
            
        return auth_headers


# --- Vulnerability Models ---

class Evidence(BaseModel):
    """Evidence of a vulnerability."""
    baseline_request: Dict[str, Any]
    baseline_response: Dict[str, Any]
    attack_request: Dict[str, Any]
    attack_response: Dict[str, Any]
    comparison_details: Dict[str, Any] = Field(default_factory=dict)
    sensitive_fields_exposed: List[str] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """A detected vulnerability."""
    id: str
    title: str
    severity: Severity
    vuln_type: str  # e.g., "horizontal_escalation", "vertical_escalation"
    endpoint: str
    method: HttpMethod
    
    # Details
    description: str
    impact: str
    
    # Evidence
    evidence: Evidence
    
    # Victim and attacker info
    victim_user: str
    attacker_user: str
    
    # References
    cwe: str = "CWE-639"
    cvss_score: float = Field(default=7.5, ge=0.0, le=10.0)
    owasp_ref: str = "API1:2023 Broken Object Level Authorization"
    
    # Remediation
    remediation: str = ""


# --- Scan Result Models ---

class EndpointResult(BaseModel):
    """Result of testing a single endpoint."""
    endpoint: Endpoint
    tested: bool = False
    vulnerable: bool = False
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    error: Optional[str] = None


class ScanResult(BaseModel):
    """Complete scan result."""
    scan_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Configuration used
    config: Dict[str, Any]
    
    # Results
    endpoints_discovered: int = 0
    endpoints_scanned: int = 0
    endpoint_results: List[EndpointResult] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    
    # Status
    status: str = "pending"  # pending, running, completed, failed
    error_message: Optional[str] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def count_by_severity(self, severity: Severity) -> int:
        """Count vulnerabilities by severity."""
        return sum(1 for v in self.vulnerabilities if v.severity == severity)
