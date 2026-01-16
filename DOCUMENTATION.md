# CrossCheck IDOR Scanner - Official Documentation

**Version:** 2.0.0  
**Repository:** [https://github.com/ruwithma/crosscheck](https://github.com/ruwithma/crosscheck)

---

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Advanced Usage](#advanced-usage)
   - [Headless Crawling](#headless-crawling)
   - [HAR File Import](#har-file-import)
   - [Burp Suite Integration](#burp-suite-integration)
6. [Configuration](#configuration)
   - [Bug Bounty Presets](#bug-bounty-presets)
   - [Custom Authentication](#custom-authentication)
7. [Detection Modules](#detection-modules)
8. [Architecture](#architecture)
9. [Legal Disclaimer](#legal-disclaimer)

---

## 1. Introduction

**CrossCheck** is a specialized security scanner designed to detect **Broken Access Control** vulnerabilities (OWASP Top 10 - A01:2021) in REST APIs. Unlike generic web scanners that rely on simple status code checks (403 vs 200), CrossCheck uses **semantic response comparison** to identify subtle data leaks and privilege escalation issues.

### Key Features
- **Smart Idempotent Fuzzing**: Replays requests with different user sessions to detect data leaks.
- **Deep Diffing**: Compares JSON responses structurally to find leaked PII or sensitive fields.
- **Auto-Bypass**: Automatically attempts 403 bypass techniques (headers, path manipulation).
- **Format Agnostic**: Detects IDORs in URL parameters (`/users/123`), JSON bodies (`{"id": 123}`), and GraphQL.

---

## 2. Installation

### Prerequisites
- Python 3.10 or higher
- `pip` package manager
- (Optional) Playwright for headless crawling

### Standard Install
```bash
git clone https://github.com/ruwithma/crosscheck.git
cd crosscheck
pip install -e .
```

### Install with Headless Crawler Support
```bash
pip install -e ".[dev]"
playwright install chromium
```

---

## 3. Quick Start

To perform a scan, you need two valid accounts on the target application:
1.  **Attacker (User A)**: The account used to send the malicious requests.
2.  **Victim (User B)**: The account whose data you attempt to access.

### Step 1: Export Cookies
Log into the target website with **User A** (Attacker) and export cookies:
- **Option A (Easy)**: Use the "Cookie-Editor" browser extension -> Export as JSON. Save to `cookies.json`.
- **Option B (Manual)**: Open DevTools -> Console -> `document.cookie`. Save to `cookies.txt`.

### Step 2: Run the Scan
```bash
idor-scanner scan https://api.target.com \
    --cookies cookies.json \
    --user1 "attacker" \
    --user2 "victim"
```

The scanner will:
1.  Crawl the API to find endpoints.
2.  Identify resource IDs (e.g., user IDs, order IDs).
3.  Attempt to access Victim's resources using Attacker's session.
4.  Report any successful data leaks.

---

## 4. Core Concepts

### The "Attacker vs. Victim" Model
IDOR scans require context. You cannot find an IDOR with just one user.
- **Baseline**: Request resource as **Victim** (Should be 200 OK).
- **Attack**: Request SAME resource as **Attacker** (Should be 403 Forbidden).
- **Vulnerability**: If Attack returns 200 OK **AND** the data matches the Victim's data, it's an IDOR.

### Auth Strings
When not using a `cookies.json` file, you can pass credentials manually:
Format: `username` (if just using cookies) or `username:password:type`.
- `alice:secret:bearer` -> Adds `Authorization: Bearer secret`
- `bob:key123:api_key` -> Adds `X-API-Key: key123`

---

## 5. Advanced Usage

### Headless Crawling 🤖
Don't have a list of API endpoints? Let the bot find them.
```bash
idor-scanner scan https://target.com \
    --headless \
    --cookies cookies.json \
    --user1 "attacker" --user2 "victim"
```
This launches a browser, logs in (using your cookies), navigates the site, and captures all API traffic to build a scan list automatically.

### HAR File Import 📂
If you recorded a session in your browser (DevTools -> Network -> Export HAR):
```bash
idor-scanner scan https://target.com \
    --har specific_flow.har \
    ...
```
This is excellent for complex workflows like "Checkout" or "Settings Change" that a crawler might miss.

### Burp Suite Integration 🦊
Proxy all traffic through Burp Suite to analyze the scanner's behavior.
```bash
idor-scanner scan ... --proxy http://127.0.0.1:8080
```

---

## 6. Configuration

### Bug Bounty Presets
CrossCheck comes with optimized presets for popular bug bounty platforms.
```bash
idor-scanner scan ... --bounty inditex
```
**Available Presets:** (`idor-scanner bounty-list`)
- `inditex` (Zara): 5 req/s, Custom User-Agent.
- `notion`: 10 req/s, JSON body fuzzing focus.
- `doordash`: High rate limit, PII detection.
- `tinder`: API-focused, mobile user-agents.

### Rate Limiting
Avoid getting WAF-banned by controlling speed:
```bash
--rate-limit 2  # 2 requests per second (Safe)
--rate-limit 50 # 50 requests per second (Aggressive)
```

---

## 7. Detection Modules (v2.0)

| Module | Description |
|--------|-------------|
| **Horizontal Escalation** | Can User A see User B's orders? |
| **Vertical Escalation** | Can User A access `/admin` endpoints? |
| **Unauthenticated Access** | Can an anonymous user see this data? |
| **GraphQL Analysis** | Introspection, batching, and mutation fuzzing. |
| **JWT Analysis** | `alg:none` bypass, signature stripping. |
| **Mass Assignment** | Privilege escalation via JSON field injection (`role: admin`). |
| **Parameter Pollution** | WAF bypass via `id=attacker&id=victim`. |
| **API Versioning** | Checks `/v1/` if `/v2/` is secure. |

---

## 8. Architecture

1.  **Discovery Layer**:
    - **Crawlers**: HTML/Headless browsers find links.
    - **Importers**: HAR/OpenAPI parsers load definitions.
    - **Analyzer**: Identifies potential IDs (UUIDs, integers) in paths and bodies.

2.  **Fuzzing Engine**:
    - Generates "Attack Requests" by swapping IDs or Sessions.
    - Handles "Body Fuzzing" for JSON APIs (replacing `{"id": "..."}`).

3.  **Comparator Engine**:
    - Receives `(Baseline Response, Attack Response)`.
    - **DeepDiff**: Calculates structural difference.
    - **PII Detector**: Scans for "email", "phone", "address" in Attack Response.
    - **Decision**: IF `Attack Status == 200` AND `Similarity > 90%` -> **VULNERABLE**.

4.  **Reporting**:
    - Outputs findings to Terminal, JSON, HTML, and Markdown.

---

## 9. Legal Disclaimer

**CrossCheck** is for **educational and authorized security testing purposes only**.
- Do not use this tool on systems you do not own or do not have explicit permission to test.
- The authors are not responsible for any damage or legal consequences caused by the misuse of this tool.
- Always adhere to the specific **Bug Bounty Program Rules** (e.g., rate limits, out-of-scope domains).

---

*Generated for CrossCheck v2.0*
