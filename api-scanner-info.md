# API Access Control Scanner - Complete Project Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [The Problem We're Solving](#the-problem-were-solving)
3. [Technical Architecture](#technical-architecture)
4. [Core Features](#core-features)
5. [Implementation Roadmap](#implementation-roadmap)
6. [Technology Stack](#technology-stack)
7. [Detailed Feature Breakdown](#detailed-feature-breakdown)
8. [Testing Strategy](#testing-strategy)
9. [Deployment & Distribution](#deployment--distribution)
10. [Career & Portfolio Strategy](#career--portfolio-strategy)
11. [Future Expansion](#future-expansion)
12. [Resources & References](#resources--references)

---

## Project Overview

### What Is This?
A specialized security scanner that detects **Broken Access Control vulnerabilities** (IDOR/BOLA) in REST APIs. Unlike generic scanners that test many things poorly, this tool focuses on doing ONE thing exceptionally well.

### Target Users
- Security researchers
- Penetration testers
- Bug bounty hunters
- DevSecOps teams
- API developers

### Key Differentiators
- **Smart detection**: Semantic response comparison, not just status codes
- **Multi-user testing**: Requires multiple user sessions for accurate testing
- **Low false positives**: <10% vs 60-70% in generic tools
- **Actionable reports**: Clear PoC with exact reproduction steps
- **Production-ready**: Async, rate-limited, CI/CD friendly

### Project Goals
- **Primary**: Build a tool that finds REAL vulnerabilities
- **Secondary**: Create an impressive portfolio project
- **Tertiary**: Learn production-quality security tool development
- **Bonus**: Earn bug bounties and build reputation

---

## The Problem We're Solving

### What is IDOR (Insecure Direct Object Reference)?

**Simple Explanation:**
When an application exposes a reference to an internal object (like a database key) and doesn't properly check if the user should have access to it.

**Real-World Example:**
```
Alice's request: GET /api/orders/12345
Response: { order_id: 12345, user: "alice", items: [...], total: 50 }

Bob's request: GET /api/orders/12345 (Alice's order!)
Response: { order_id: 12345, user: "alice", items: [...], total: 50 }

🚨 Bob can see Alice's order = IDOR vulnerability
```

### Why This Matters

**Statistics:**
- #1 vulnerability in OWASP API Security Top 10 (2023)
- Found in 90%+ of APIs during penetration tests
- Average severity: HIGH to CRITICAL
- Common in fintech, healthcare, e-commerce, social media

**Real Impact:**
- Uber 2016: Drivers could access other drivers' data
- Facebook 2020: View private photos via Graph API
- Venmo: Transaction history exposed
- Instagram: Private account data leakage

**Bug Bounty Value:**
- Low: $500 - $2,000
- Medium: $2,000 - $5,000
- High: $5,000 - $15,000
- Critical: $15,000 - $50,000+

### Why Existing Tools Fail

**Problem 1: High False Positives**
```
Generic Scanner:
- Sees status 200 → Flags as vulnerable
- Reality: Public endpoint that should return 200
- Result: 70% false positive rate
```

**Problem 2: Missed Vulnerabilities**
```
Generic Scanner:
- Checks: if status_code == 200: vulnerable
- Misses: Partial data leakage (status 200 but filtered data)
- Misses: Information disclosure in error messages
- Misses: Timing attacks
```

**Problem 3: No Context Understanding**
```
Generic Scanner:
/api/users/123 returns data
/api/users/456 returns data
Scanner: "Both return 200, no issue"

Reality:
User 123 accessing their own data: ✅ OK
User 123 accessing user 456's data: 🚨 VULNERABLE
```

### Our Solution

**Smart Multi-User Testing:**
1. Authenticate as User A
2. Access User A's resources (baseline)
3. Authenticate as User B
4. Attempt to access User A's resources
5. Compare responses semantically
6. Detect unauthorized data access

**Intelligent Analysis:**
- Response body comparison (not just status)
- Detects partial data leakage
- Identifies sensitive fields
- Recognizes error message patterns
- Timing analysis for blind IDOR

---

## Technical Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Interface                         │
│                   (Typer + Rich UI)                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scanner Core Engine                       │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐  │
│  │ Discovery  │  │ Session    │  │   Vulnerability     │  │
│  │ Module     │  │ Manager    │  │   Check Engine      │  │
│  └────────────┘  └────────────┘  └─────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   HTTP Client Layer                          │
│              (httpx - Async/Concurrent)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Analysis & Reporting                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐  │
│  │ Response     │  │ Vulnerability │  │   Report        │  │
│  │ Comparator   │  │ Classifier    │  │   Generator     │  │
│  └──────────────┘  └──────────────┘  └─────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Storage Layer                             │
│              (SQLite for scan history)                       │
└─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### 1. Discovery Module
**Purpose:** Find all API endpoints and extract testable resources

**Capabilities:**
- Crawl API from base URL
- Parse OpenAPI/Swagger documentation
- Detect common API patterns (/v1, /api, /graphql)
- Extract resource IDs from URLs
- Identify authentication endpoints
- Map API structure

**Algorithms:**
```python
# ID Extraction Patterns
patterns = [
    r'/(\d+)',              # Numeric IDs: /users/123
    r'/([a-f0-9-]{36})',    # UUIDs: /orders/550e8400-...
    r'/([A-Za-z0-9_-]+)',   # Alphanumeric: /posts/abc123
]

# Common Endpoint Patterns
endpoints = [
    '/api/users/{id}',
    '/api/v1/accounts/{id}',
    '/api/orders/{id}/items',
    '/api/documents/{id}/download',
]
```

#### 2. Session Manager
**Purpose:** Handle multiple authenticated sessions simultaneously

**Features:**
- Store credentials securely (in-memory only)
- Maintain session tokens/cookies
- Auto-refresh expired tokens
- Parallel request handling
- Rate limiting per session

**Data Structure:**
```python
Session {
    user_id: str
    role: str  # "user" | "admin" | "guest"
    auth_token: str
    cookies: dict
    headers: dict
    created_at: datetime
    last_used: datetime
}
```

#### 3. Vulnerability Check Engine
**Purpose:** Core testing logic for access control issues

**Test Types:**
1. **Horizontal Privilege Escalation**
   - Same role, different user
   - User A → User B's resources

2. **Vertical Privilege Escalation**
   - Different roles
   - Regular user → Admin resources

3. **HTTP Method Tampering**
   - GET blocked but POST works
   - PUT/PATCH/DELETE bypasses

4. **Parameter Pollution**
   - Multiple ID parameters
   - Hidden admin flags

**Test Flow:**
```
For each endpoint with ID:
  1. Get baseline (User A accessing own resource)
  2. Test horizontal (User B accessing User A's resource)
  3. Test vertical (User accessing Admin resource)
  4. Test method tampering (different HTTP methods)
  5. Test parameter variations
  6. Analyze all responses
  7. Classify vulnerability severity
```

#### 4. Response Comparator
**Purpose:** Intelligently compare API responses

**Comparison Techniques:**
```python
# Not just status code comparison
def compare_responses(baseline, test):
    # 1. Status code
    if baseline.status != test.status:
        return analyze_status_difference()
    
    # 2. Response body (semantic diff)
    if has_same_data(baseline.json, test.json):
        return VULNERABLE
    
    # 3. Sensitive field detection
    if contains_sensitive_data(test.json):
        return CRITICAL
    
    # 4. Partial leakage
    if has_partial_overlap(baseline.json, test.json):
        return POTENTIAL_VULN
    
    # 5. Error message analysis
    if reveals_info(test.error_message):
        return INFO_DISCLOSURE
    
    # 6. Timing analysis
    if timing_difference(baseline, test) > threshold:
        return BLIND_IDOR
```

**Semantic Diff Example:**
```python
# DeepDiff library usage
from deepdiff import DeepDiff

baseline = {
    "user_id": 123,
    "email": "alice@example.com",
    "orders": [...]
}

test = {
    "user_id": 123,
    "email": "alice@example.com",  # Bob shouldn't see this!
    "orders": [...]
}

diff = DeepDiff(baseline, test, ignore_order=True)
# If diff is empty → responses are identical → VULNERABLE
```

#### 5. Report Generator
**Purpose:** Create professional vulnerability reports

**Output Formats:**
1. **Terminal** (Rich formatting, colors, tables)
2. **JSON** (for automation/parsing)
3. **HTML** (professional client report)
4. **Markdown** (for bug bounties/GitHub)
5. **PDF** (via HTML conversion)

**Report Structure:**
```markdown
# Vulnerability Report

## Executive Summary
- Total endpoints scanned: 47
- Vulnerabilities found: 3
- Critical: 1, High: 2, Medium: 0, Low: 0

## Critical Findings

### [CRITICAL] Broken Access Control in Orders API
**Endpoint:** GET /api/orders/{id}
**CWE:** CWE-639 (Authorization Bypass)
**CVSS:** 8.1 (High)

**Description:**
Any authenticated user can access any other user's order details
by manipulating the order ID in the API endpoint.

**Proof of Concept:**
1. Authenticate as alice@example.com (User ID: 123)
2. Create an order (Order ID: 456)
3. Authenticate as bob@example.com (User ID: 789)
4. Send: GET /api/orders/456
5. Observe: Bob receives Alice's complete order details

**Evidence:**
Request:
```
GET /api/orders/456 HTTP/1.1
Host: api.example.com
Authorization: Bearer bob_token_here
```

Response:
```json
{
  "order_id": 456,
  "user_id": 123,
  "user_email": "alice@example.com",
  "items": [...],
  "total": 129.99,
  "shipping_address": "123 Private St, ..."
}
```

**Impact:**
- All 10,000+ users' orders are exposed
- Contains PII (emails, addresses, phone numbers)
- Payment method information visible
- Order history can be enumerated

**Remediation:**
```python
# Add authorization check
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if order.user_id != current_user.id:
        return {"error": "Unauthorized"}, 403
    return order.to_json()
```

**References:**
- OWASP API Security Top 10 2023: API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
```

---

## Core Features

### Must-Have (MVP - Week 1-4)

#### 1. Multi-User Session Management
```
Features:
- Support 2+ simultaneous user sessions
- Automatic token/cookie management
- Session isolation (no cross-contamination)
- Support for Bearer tokens, Basic Auth, Cookie auth, API keys

CLI Example:
$ idor-scanner scan https://api.example.com \
    --user1 "alice:password123" \
    --user2 "bob:password456" \
    --admin "admin:supersecret"
```

#### 2. Smart Endpoint Discovery
```
Methods:
- Passive: Parse OpenAPI/Swagger docs
- Active: Crawl from base URL
- Manual: Load from file (endpoints.txt)
- Proxy: Import from Burp Suite

Output:
- List of all endpoints
- Identified resources with IDs
- Authentication requirements
- HTTP methods supported
```

#### 3. IDOR Detection Core
```
Tests Performed:
✓ Horizontal privilege escalation (user → user)
✓ Vertical privilege escalation (user → admin)
✓ HTTP method tampering (GET vs POST vs PUT vs DELETE)
✓ Response comparison (semantic diff)
✓ Sensitive data detection
✓ Error message analysis

Accuracy Targets:
- True Positive Rate: >95%
- False Positive Rate: <10%
```

#### 4. Professional Reporting
```
Formats:
- Terminal: Rich formatted, colored output
- JSON: Machine-readable for automation
- HTML: Professional client report with CSS
- Markdown: Bug bounty submissions

Contents:
- Executive summary with metrics
- Detailed findings with severity
- Proof of concept for each vuln
- Remediation recommendations
- OWASP/CWE mappings
```

#### 5. CLI Interface
```
Commands:
$ idor-scanner scan <target>
$ idor-scanner discover <target>
$ idor-scanner report <scan-id>
$ idor-scanner config
$ idor-scanner --help

Features:
- Progress bars
- Real-time updates
- Colorized output
- Verbose/debug modes
- Scan history
```

### Should-Have (Post-MVP - Week 5-8)

#### 6. Advanced Detection
```
- Blind IDOR via timing attacks
- Indirect object references
- UUID/GUID enumeration
- Base64-encoded ID testing
- JWT manipulation
- GraphQL query testing
```

#### 7. Stealth Mode
```
- Randomized user agents
- Request delays/jitter
- Traffic pattern mimicry
- Proxy support (HTTP/SOCKS)
- Custom headers
```

#### 8. Performance Features
```
- Async/concurrent scanning (100+ req/sec)
- Smart rate limiting
- Request caching
- Resume interrupted scans
- Incremental scanning
```

#### 9. CI/CD Integration
```
- Exit codes for pipeline integration
- Diff mode (compare scans)
- Baseline mode (track over time)
- Fail on critical findings
- JSON output for parsing
```

### Could-Have (Future - Month 3+)

#### 10. Web Dashboard
```
- Visual scan reports
- Historical data tracking
- Team collaboration
- Scan scheduling
- Real-time monitoring
```

#### 11. Plugin System
```
- Custom vulnerability checks
- Authentication plugins
- Report format plugins
- Integration plugins (Slack, Jira)
```

#### 12. AI Enhancement
```
- Smart payload generation
- Pattern recognition
- False positive reduction
- Automated exploit generation
- Natural language reports
```

---

## Implementation Roadmap

### Week 1: Foundation

**Day 1-2: Project Setup**
```
Tasks:
□ Initialize git repository
□ Setup Python project structure
□ Configure poetry/pip for dependencies
□ Create basic CLI with Typer
□ Implement logging system
□ Setup testing framework (pytest)

Deliverables:
- Working CLI skeleton
- Project can be installed via pip
- Basic tests passing
```

**Day 3-4: HTTP Client Layer**
```
Tasks:
□ Implement async HTTP client (httpx)
□ Add retry logic with exponential backoff
□ Implement request/response logging
□ Add timeout handling
□ Create session management
□ SSL/TLS certificate handling

Deliverables:
- Reliable HTTP client
- Can make authenticated requests
- Handles errors gracefully
```

**Day 5-7: Multi-User Session Manager**
```
Tasks:
□ Design Session class
□ Implement authentication flows:
  - Bearer token
  - Basic Auth
  - Cookie-based
  - API key
□ Session storage and retrieval
□ Token refresh logic
□ Parallel session handling

Deliverables:
- Can authenticate multiple users
- Sessions don't interfere
- Automatic token management
```

### Week 2: Core Detection

**Day 1-2: Endpoint Discovery**
```
Tasks:
□ OpenAPI/Swagger parser
□ Simple crawler (follow links)
□ ID extraction from URLs
□ Endpoint categorization
□ Manual endpoint import

Deliverables:
- List all API endpoints from target
- Identify resources with IDs
- Save endpoint map
```

**Day 3-4: Response Comparator**
```
Tasks:
□ Implement DeepDiff integration
□ Semantic JSON comparison
□ Sensitive field detection
□ Status code analysis
□ Error message parsing

Deliverables:
- Can compare two responses
- Identify differences
- Classify severity
```

**Day 5-7: IDOR Test Engine**
```
Tasks:
□ Horizontal escalation tests
□ Vertical escalation tests
□ HTTP method tampering
□ Test orchestration
□ Result collection

Deliverables:
- Working IDOR detection
- Can test user A vs user B
- Detects actual vulnerabilities
```

### Week 3: Advanced Features

**Day 1-2: Smart Analysis**
```
Tasks:
□ Vulnerability classification
□ Severity scoring (CVSS)
□ False positive filtering
□ Evidence collection
□ Impact assessment

Deliverables:
- Accurate severity ratings
- Low false positive rate
- Clear evidence for each finding
```

**Day 3-4: Performance Optimization**
```
Tasks:
□ Implement async scanning
□ Add rate limiting
□ Request caching
□ Connection pooling
□ Progress tracking

Deliverables:
- Scans 100+ requests/second
- Doesn't overwhelm target
- Shows progress in real-time
```

**Day 5-7: Advanced Tests**
```
Tasks:
□ Parameter pollution
□ Indirect object references
□ UUID/GUID handling
□ Base64 ID testing
□ Edge case handling

Deliverables:
- Catches subtle vulnerabilities
- Tests multiple attack vectors
```

### Week 4: Polish & Release

**Day 1-2: Report Generation**
```
Tasks:
□ Terminal report with Rich
□ JSON export
□ HTML report with CSS
□ Markdown for bug bounties
□ PDF generation

Deliverables:
- Professional-looking reports
- Multiple output formats
- Clear, actionable findings
```

**Day 3-4: Testing & Bug Fixes**
```
Tasks:
□ Test on vulnerable apps (Juice Shop, DVWA)
□ Fix discovered bugs
□ Add error handling
□ Write comprehensive tests
□ Code cleanup

Deliverables:
- Stable, reliable tool
- All tests passing
- Clean codebase
```

**Day 5-7: Documentation & Demo**
```
Tasks:
□ Write comprehensive README
□ Create user guide
□ Record demo video
□ Write blog post
□ Prepare GitHub release

Deliverables:
- Complete documentation
- Demo video showing real vulns
- Blog post published
- v1.0.0 release on GitHub
```

---

## Technology Stack

### Core Technologies

#### Programming Language
**Python 3.10+**
- Reason: Standard for security tools, great libraries
- Features needed: Type hints, async/await, dataclasses
- Compatibility: Cross-platform (Windows, macOS, Linux)

#### HTTP Client
**httpx**
```python
# Why httpx over requests?
✓ Async/await support (performance)
✓ HTTP/2 support
✓ Better timeout handling
✓ Connection pooling
✓ Modern API

Example:
import httpx

async with httpx.AsyncClient() as client:
    response = await client.get('https://api.example.com')
```

#### CLI Framework
**Typer**
```python
# Clean, type-safe CLI
import typer

app = typer.Typer()

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target API URL"),
    user1: str = typer.Option(..., help="User 1 credentials"),
    verbose: bool = typer.Option(False, "--verbose", "-v")
):
    """Scan API for IDOR vulnerabilities"""
    ...
```

#### Terminal UI
**Rich**
```python
# Beautiful terminal output
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
console.print("[bold green]Scan Complete![/bold green]")

# Progress bars
for endpoint in track(endpoints, description="Scanning..."):
    scan(endpoint)
```

### Supporting Libraries

#### Data Validation
**Pydantic**
```python
from pydantic import BaseModel, HttpUrl

class ScanConfig(BaseModel):
    target: HttpUrl
    users: List[User]
    timeout: int = 30
    rate_limit: int = 10
```

#### Response Comparison
**DeepDiff**
```python
from deepdiff import DeepDiff

diff = DeepDiff(response1, response2, ignore_order=True)
if not diff:
    # Responses are identical → potential IDOR
    report_vulnerability()
```

#### JSON Processing
**orjson**
- Fastest JSON library for Python
- Handles large responses efficiently

#### Database
**SQLite3** (built-in)
```python
# Store scan history
schema = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    target TEXT,
    timestamp DATETIME,
    findings INTEGER,
    status TEXT
);

CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    endpoint TEXT,
    severity TEXT,
    details JSON,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

### Development Tools

#### Package Management
**Poetry** or **pip-tools**
```toml
# pyproject.toml
[tool.poetry.dependencies]
python = "^3.10"
httpx = "^0.24.0"
typer = "^0.9.0"
rich = "^13.0.0"
pydantic = "^2.0.0"
deepdiff = "^6.0.0"
```

#### Testing
**pytest** + **pytest-asyncio**
```python
@pytest.mark.asyncio
async def test_idor_detection():
    scanner = IDORScanner(config)
    result = await scanner.test_endpoint(
        "/api/users/123",
        user_a_session,
        user_b_session
    )
    assert result.is_vulnerable
```

#### Code Quality
- **black**: Code formatting
- **ruff**: Fast linting (replaces flake8, isort)
- **mypy**: Static type checking
- **pre-commit**: Git hooks for quality checks

#### CI/CD
**GitHub Actions**
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: |
          pip install -e .
          pytest
```

---

## Detailed Feature Breakdown

### 1. Endpoint Discovery Engine

**Input Methods:**

**A. Automated Crawling**
```python
async def crawl_api(base_url: str, max_depth: int = 3):
    """
    Crawl API starting from base URL
    Follow links, extract endpoints
    """
    discovered = set()
    queue = [(base_url, 0)]
    
    while queue:
        url, depth = queue.pop(0)
        if depth > max_depth:
            continue
            
        response = await client.get(url)
        # Extract links from response
        links = extract_links(response)
        # Extract API endpoints
        endpoints = extract_api_calls(response)
        
        discovered.update(endpoints)
        queue.extend((link, depth + 1) for link in links)
    
    return discovered
```

**B. OpenAPI/Swagger Parsing**
```python
def parse_openapi(spec_url: str) -> List[Endpoint]:
    """
    Parse OpenAPI/Swagger specification
    Extract all endpoints with parameters
    """
    spec = requests.get(spec_url).json()
    endpoints = []
    
    for path, methods in spec['paths'].items():
        for method, details in methods.items():
            endpoint = Endpoint(
                path=path,
                method=method.upper(),
                parameters=extract_parameters(details),
                auth_required=requires_auth(details)
            )
            endpoints.append(endpoint)
    
    return endpoints
```

**C. Proxy Import (Burp Suite)**
```python
def import_from_burp(burp_state_file: str):
    """
    Import endpoints from Burp Suite state file
    Parse XML, extract HTTP history
    """
    tree = ET.parse(burp_state_file)
    for item in tree.findall('.//item'):
        method = item.find('method').text
        url = item.find('url').text
        # Extract and store endpoint
```

**D. Manual Import**
```python
# endpoints.txt
GET /api/users/{id}
POST /api/orders/{order_id}
PUT /api/accounts/{account_id}/settings
DELETE /api/posts/{post_id}
```

**ID Extraction:**
```python
import re

ID_PATTERNS = [
    (r'/(\d+)(?:/|$)', 'numeric'),           # /users/123
    (r'/([a-f0-9-]{36})(?:/|$)', 'uuid'),   # UUID v4
    (r'/([A-Za-z0-9_-]+)(?:/|$)', 'alphanum'), # /posts/abc123
    (r'\?id=(\d+)', 'query_numeric'),        # ?id=123
    (r'\?id=([^&]+)', 'query_string'),       # ?id=abc
]

def extract_ids(url: str) -> List[ResourceID]:
    """Extract all potential resource IDs from URL"""
    ids = []
    for pattern, id_type in ID_PATTERNS:
        matches = re.findall(pattern, url)
        for match in matches:
            ids.append(ResourceID(value=match, type=id_type))
    return ids
```

### 2. Session Management System

**Session Object:**
```python
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

@dataclass
class Session:
    user_id: str
    role: str  # "user", "admin", "guest"
    credentials: Dict[str, str]
    auth_type: str  # "bearer", "basic", "cookie", "api_key"
    
    # Authentication data
    token: Optional[str] = None
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None
    
    # Metadata
    created_at: datetime = None
    last_used: datetime = None
    expires_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    def to_httpx_auth(self) -> Dict:
        """Convert to httpx-compatible auth dict"""
        if self.auth_type == "bearer":
            return {"Authorization": f"Bearer {self.token}"}
        elif self.auth_type == "basic":
            return {"Authorization": f"Basic {self.token}"}
        # ... other types
```

**Session Manager:**
```python
class SessionManager:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.client = httpx.AsyncClient()
    
    async def authenticate(
        self,
        user_id: str,
        credentials: Dict,
        auth_endpoint: str
    ) -> Session:
        """Authenticate user and create session"""
        
        # Login request
        response = await self.client.post(
            auth_endpoint,
            json=credentials
        )
        
        if response.status_code != 200:
            raise AuthenticationError("Login failed")
        
        # Extract token/cookies
        token = response.json().get('token')
        cookies = response.cookies
        
        # Create session
        session = Session(
            user_id=user_id,
            role=credentials.get('role', 'user'),
            credentials=credentials,
            auth_type="bearer",
            token=token,
            cookies=dict(cookies),
            created_at=datetime.now()
        )
        
        self.sessions[user_id] = session
        return session
    
    async def refresh_if_needed(self, session: Session):
        """Auto-refresh expired tokens"""
        if session.is_expired():
            # Re-authenticate
            new_session = await self.authenticate(
                session.user_id,
                session.credentials,
                auth_endpoint
            )
            self.sessions[session.user_id] = new_session
    
    async def make_request(
        self,
        session: Session,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """Make authenticated request"""
        
        await self.refresh_if_needed(session)
        
        # Add authentication
        headers = kwargs.get('headers', {})
        headers.update(session.to_httpx_auth())
        
        cookies = kwargs.get('cookies', {})
        cookies.update(session.cookies or {})
        
        response = await self.client.request(
            method,
            url,
            headers=headers,
            cookies=cookies,
            **kwargs
        )
        
        session.last_used = datetime.now()
        return response
```

### 3. IDOR Detection Algorithm

**Core Testing Flow:**
```python
class IDORDetector:
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        session_a: Session,
        session_b: Session,
        admin_session: Optional[Session] = None
    ) -> List[Finding]:
        """
        Test endpoint for IDOR vulnerabilities
        Returns list of findings
        """
        findings = []
        
        # Step 1: Baseline (User A accesses own resource)
        baseline = await self.get_baseline(endpoint, session_a)
        if not baseline:
            return findings  # Endpoint not accessible
        
        # Step 2: Horizontal escalation (User B → User A's resource)
        horizontal = await self.test_horizontal(
            endpoint, 
            baseline, 
            session_a, 
            session_b
        )
        if horizontal:
            findings.append(horizontal)
        
        # Step 3: Vertical escalation (User → Admin resource)
        if admin_session:
            vertical = await self.test_vertical(
                endpoint,
                session_a,
                admin_session
            )
            if vertical:
                findings.append(vertical)
        
        # Step 4: Method tampering
        method_findings = await self.test_method_tampering(
            endpoint,
            session_a,
            session_b
        )
        findings.extend(method_findings)
        
        # Step 5: Parameter pollution
        pollution_findings = await self.test_parameter_pollution(
            endpoint,
            session_a,
            session_b
        )
        findings.extend(pollution_findings)
        
        return findings
    
    async def test_horizontal(
        self,
        endpoint: Endpoint,
        baseline: Response,
        victim_session: Session,
        attacker_session: Session
    ) -> Optional[Finding]:
        """Test if User B can access User A's resource"""
        
        # User B tries to access User A's resource
        url = endpoint.url_for(baseline.resource_id)
        
        response = await self.session_manager.make_request(
            attacker_session,
            endpoint.method,
            url
        )
        
        # Analyze response
        vuln = self.response_comparator.compare(
            baseline.response,
            response,
            check_type="horizontal"
        )
        
        if vuln:
            return Finding(
                type="IDOR - Horizontal Privilege Escalation",
                severity="HIGH",
                endpoint=endpoint,
                victim=victim_session.user_id,
                attacker=attacker_session.user_id,
                evidence={
                    "baseline_request": baseline.request,
                    "baseline_response": baseline.response,
                    "attack_request": response.request,
                    "attack_response": response,
                    "comparison": vuln
                }
            )
        
        return None
```

**Response Comparison:**
```python
class ResponseComparator:
    def __init__(self):
        self.sensitive_fields = [
            'email', 'phone', 'ssn', 'password', 'token',
            'address', 'credit_card', 'user_id', 'account_id'
        ]
    
    def compare(
        self,
        baseline: httpx.Response,
        test: httpx.Response,
        check_type: str
    ) -> Optional[Vulnerability]:
        """
        Intelligent response comparison
        Returns Vulnerability if access control is broken
        """
        
        # Quick checks
        if test.status_code == 403 or test.status_code == 401:
            return None  # Properly blocked
        
        if test.status_code == 404:
            return None  # Resource not found (OK)
        
        if test.status_code >= 500:
            return None  # Server error (not IDOR)
        
        # Both returned 200, now compare content
        if baseline.status_code == 200 and test.status_code == 200:
            return self._compare_success_responses(baseline, test)
        
        # Different status codes but test succeeded
        if test.status_code == 200:
            return self._analyze_unexpected_success(baseline, test)
        
        return None
    
    def _compare_success_responses(
        self,
        baseline: httpx.Response,
        test: httpx.Response
    ) -> Optional[Vulnerability]:
        """Compare two successful responses"""
        
        try:
            baseline_data = baseline.json()
            test_data = test.json()
        except:
            # Not JSON, compare as text
            return self._compare_text(baseline.text, test.text)
        
        # Use DeepDiff for semantic comparison
        diff = DeepDiff(
            baseline_data,
            test_data,
            ignore_order=True,
            exclude_paths=["root['timestamp']", "root['request_id']"]
        )
        
        # Responses are identical → VULNERABLE
        if not diff:
            severity = self._assess_severity(baseline_data)
            return Vulnerability(
                type="identical_response",
                severity=severity,
                description="Attacker received identical data as victim",
                evidence={
                    "baseline": baseline_data,
                    "test": test_data,
                    "sensitive_fields": self._find_sensitive_fields(baseline_data)
                }
            )
        
        # Partial data leakage
        similarity = self._calculate_similarity(baseline_data, test_data)
        if similarity > 0.7:  # 70% similar
            return Vulnerability(
                type="partial_disclosure",
                severity="MEDIUM",
                description=f"Partial data leakage ({similarity*100:.1f}% similarity)",
                evidence={
                    "differences": diff,
                    "similarity_score": similarity
                }
            )
        
        return None
    
    def _find_sensitive_fields(self, data: dict) -> List[str]:
        """Identify sensitive fields in response"""
        found = []
        
        def search(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if key.lower() in self.sensitive_fields:
                        found.append(current_path)
                    search(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search(item, f"{path}[{i}]")
        
        search(data)
        return found
    
    def _assess_severity(self, data: dict) -> str:
        """Assess vulnerability severity based on data sensitivity"""
        sensitive = self._find_sensitive_fields(data)
        
        critical_fields = ['ssn', 'password', 'credit_card', 'token']
        if any(field in str(sensitive).lower() for field in critical_fields):
            return "CRITICAL"
        
        if len(sensitive) > 3:
            return "HIGH"
        
        if len(sensitive) > 0:
            return "MEDIUM"
        
        return "LOW"
```

### 4. Report Generation System

**Report Template (Markdown):**
```python
REPORT_TEMPLATE = """
# API Security Scan Report

**Target:** {target}
**Scan Date:** {scan_date}
**Scanner Version:** {version}
**Scan Duration:** {duration}

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Endpoints Scanned | {total_endpoints} |
| Vulnerabilities Found | {total_vulns} |
| Critical | {critical_count} |
| High | {high_count} |
| Medium | {medium_count} |
| Low | {low_count} |

---

## Vulnerability Findings

{findings}

---

## Remediation Summary

{remediation}

---

## Appendix

### Scan Configuration
```json
{config}
```

### Endpoints Tested
{endpoint_list}
"""

FINDING_TEMPLATE = """
### [{severity}] {title}

**Endpoint:** `{method} {endpoint}`  
**Vulnerability Type:** {vuln_type}  
**CWE:** {cwe}  
**CVSS Score:** {cvss}  

#### Description
{description}

#### Proof of Concept

**Step 1:** Authenticate as victim user
```bash
curl -X POST {auth_url} \\
  -H "Content-Type: application/json" \\
  -d '{{"username": "{victim}", "password": "***"}}'
```

**Step 2:** Victim accesses their resource
```bash
curl -X {method} {victim_request_url} \\
  -H "Authorization: Bearer {victim_token}"
```

**Response:**
```json
{victim_response}
```

**Step 3:** Authenticate as attacker user
```bash
curl -X POST {auth_url} \\
  -H "Content-Type: application/json" \\
  -d '{{"username": "{attacker}", "password": "***"}}'
```

**Step 4:** Attacker accesses victim's resource
```bash
curl -X {method} {attack_request_url} \\
  -H "Authorization: Bearer {attacker_token}"
```

**Response:**
```json
{attack_response}
```

#### Impact
{impact}

#### Remediation
```python
{remediation_code}
```

#### References
- OWASP API Security Top 10: {owasp_ref}
- CWE-{cwe_num}: {cwe_link}

---
"""
```

**Report Generator:**
```python
class ReportGenerator:
    def generate_markdown(self, scan_result: ScanResult) -> str:
        """Generate markdown report"""
        
        findings_md = ""
        for finding in scan_result.vulnerabilities:
            findings_md += self._format_finding(finding)
        
        report = REPORT_TEMPLATE.format(
            target=scan_result.target,
            scan_date=scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            version="1.0.0",
            duration=str(scan_result.duration),
            total_endpoints=scan_result.endpoints_scanned,
            total_vulns=len(scan_result.vulnerabilities),
            critical_count=scan_result.count_by_severity('CRITICAL'),
            high_count=scan_result.count_by_severity('HIGH'),
            medium_count=scan_result.count_by_severity('MEDIUM'),
            low_count=scan_result.count_by_severity('LOW'),
            findings=findings_md,
            remediation=self._generate_remediation_summary(scan_result),
            config=json.dumps(scan_result.config, indent=2),
            endpoint_list=self._format_endpoint_list(scan_result.endpoints)
        )
        
        return report
    
    def generate_html(self, scan_result: ScanResult) -> str:
        """Generate HTML report with CSS styling"""
        
        markdown_content = self.generate_markdown(scan_result)
        
        # Convert markdown to HTML
        html_body = markdown.markdown(
            markdown_content,
            extensions=['tables', 'fenced_code', 'codehilite']
        )
        
        # Add CSS styling
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>API Security Scan Report</title>
            <style>
                {self._get_css()}
            </style>
        </head>
        <body>
            <div class="container">
                {html_body}
            </div>
        </body>
        </html>
        """
        
        return html
    
    def generate_json(self, scan_result: ScanResult) -> str:
        """Generate JSON report for automation"""
        
        return json.dumps({
            "scan_info": {
                "target": scan_result.target,
                "start_time": scan_result.start_time.isoformat(),
                "end_time": scan_result.end_time.isoformat(),
                "duration_seconds": scan_result.duration.total_seconds(),
                "scanner_version": "1.0.0"
            },
            "summary": {
                "total_endpoints": scan_result.endpoints_scanned,
                "total_vulnerabilities": len(scan_result.vulnerabilities),
                "by_severity": {
                    "critical": scan_result.count_by_severity('CRITICAL'),
                    "high": scan_result.count_by_severity('HIGH'),
                    "medium": scan_result.count_by_severity('MEDIUM'),
                    "low": scan_result.count_by_severity('LOW')
                }
            },
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "endpoint": vuln.endpoint,
                    "method": vuln.method,
                    "type": vuln.type,
                    "cwe": vuln.cwe,
                    "cvss": vuln.cvss,
                    "description": vuln.description,
                    "evidence": vuln.evidence,
                    "remediation": vuln.remediation
                }
                for vuln in scan_result.vulnerabilities
            ],
            "endpoints": [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "tested": ep.tested,
                    "vulnerable": ep.vulnerable
                }
                for ep in scan_result.endpoints
            ]
        }, indent=2)
    
    def generate_terminal(self, scan_result: ScanResult):
        """Generate beautiful terminal output using Rich"""
        
        console = Console()
        
        # Header
        console.print("\n")
        console.print("="*70, style="bold blue")
        console.print("  API SECURITY SCAN REPORT", style="bold white", justify="center")
        console.print("="*70, style="bold blue")
        console.print("\n")
        
        # Summary Table
        table = Table(title="Scan Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Target", scan_result.target)
        table.add_row("Endpoints Scanned", str(scan_result.endpoints_scanned))
        table.add_row("Duration", str(scan_result.duration))
        table.add_row("", "")
        table.add_row("Total Vulnerabilities", str(len(scan_result.vulnerabilities)))
        
        # Color-coded severity counts
        critical = scan_result.count_by_severity('CRITICAL')
        high = scan_result.count_by_severity('HIGH')
        medium = scan_result.count_by_severity('MEDIUM')
        low = scan_result.count_by_severity('LOW')
        
        if critical > 0:
            table.add_row("Critical", f"[bold red]{critical}[/bold red]")
        if high > 0:
            table.add_row("High", f"[red]{high}[/red]")
        if medium > 0:
            table.add_row("Medium", f"[yellow]{medium}[/yellow]")
        if low > 0:
            table.add_row("Low", f"[green]{low}[/green]")
        
        console.print(table)
        console.print("\n")
        
        # Findings
        if scan_result.vulnerabilities:
            console.print("[bold red]VULNERABILITIES FOUND[/bold red]\n")
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                severity_color = {
                    'CRITICAL': 'bold red',
                    'HIGH': 'red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(vuln.severity, 'white')
                
                console.print(f"[{severity_color}]#{i} [{vuln.severity}] {vuln.title}[/{severity_color}]")
                console.print(f"   Endpoint: {vuln.method} {vuln.endpoint}")
                console.print(f"   Type: {vuln.type}")
                console.print(f"   CVSS: {vuln.cvss}\n")
        else:
            console.print("[bold green]✓ No vulnerabilities found![/bold green]\n")
        
        # Footer
        console.print("="*70, style="bold blue")
        console.print(f"Report saved to: {scan_result.report_path}", style="dim")
        console.print("\n")
```

---

## Testing Strategy

### Phase 1: Unit Testing

**Test Coverage Goals:**
- Core functions: 90%+
- HTTP client: 85%+
- Detection logic: 95%+
- Report generation: 80%+

**Example Tests:**
```python
import pytest
from unittest.mock import Mock, patch
import httpx

class TestIDORDetector:
    @pytest.fixture
    def detector(self):
        return IDORDetector(config)
    
    @pytest.fixture
    def mock_sessions(self):
        return {
            'alice': Session(user_id='alice', role='user', token='token_a'),
            'bob': Session(user_id='bob', role='user', token='token_b')
        }
    
    @pytest.mark.asyncio
    async def test_detects_horizontal_escalation(self, detector, mock_sessions):
        """Test detection of horizontal privilege escalation"""
        
        # Mock responses
        alice_response = httpx.Response(
            200,
            json={"user_id": "alice", "email": "alice@example.com"}
        )
        bob_response = httpx.Response(
            200,
            json={"user_id": "alice", "email": "alice@example.com"}
        )
        
        with patch.object(detector.session_manager, 'make_request', side_effect=[alice_response, bob_response]):
            finding = await detector.test_horizontal(
                Endpoint("/api/users/alice"),
                alice_response,
                mock_sessions['alice'],
                mock_sessions['bob']
            )
        
        assert finding is not None
        assert finding.severity == "HIGH"
        assert "horizontal" in finding.type.lower()
    
    @pytest.mark.asyncio
    async def test_no_false_positive_on_authorized_access(self, detector, mock_sessions):
        """Test that authorized access doesn't trigger false positive"""
        
        alice_response = httpx.Response(
            200,
            json={"user_id": "alice", "email": "alice@example.com"}
        )
        bob_response = httpx.Response(
            403,
            json={"error": "Forbidden"}
        )
        
        with patch.object(detector.session_manager, 'make_request', side_effect=[alice_response, bob_response]):
            finding = await detector.test_horizontal(
                Endpoint("/api/users/alice"),
                alice_response,
                mock_sessions['alice'],
                mock_sessions['bob']
            )
        
        assert finding is None

class TestResponseComparator:
    def test_identical_responses_detected(self):
        """Test detection of identical responses"""
        comparator = ResponseComparator()
        
        response1 = Mock(
            status_code=200,
            json=lambda: {"user": "alice", "email": "alice@example.com"}
        )
        response2 = Mock(
            status_code=200,
            json=lambda: {"user": "alice", "email": "alice@example.com"}
        )
        
        vuln = comparator.compare(response1, response2, "horizontal")
        
        assert vuln is not None
        assert vuln.type == "identical_response"
    
    def test_properly_blocked_access(self):
        """Test that 403