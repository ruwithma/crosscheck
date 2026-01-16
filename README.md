# IDOR Scanner - API Access Control Vulnerability Scanner

A specialized security scanner that detects **Broken Access Control vulnerabilities** (IDOR/BOLA) in REST APIs through intelligent multi-user testing and semantic response comparison.

## Features

- **Smart Detection**: Semantic response comparison, not just status codes
- **Multi-User Testing**: Requires multiple user sessions for accurate testing
- **Low False Positives**: <10% vs 60-70% in generic tools
- **Actionable Reports**: Clear PoC with exact reproduction steps
- **Multiple Output Formats**: Terminal, JSON, Markdown, HTML

> 📚 **[Read the Full Documentation](DOCUMENTATION.md)** for detailed usage, configuration, and architecture guides.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/idor-scanner.git
cd idor-scanner

# Install with pip
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

## Quick Start Guide

### 1. Preparation
You need **two accounts** on the target website.
- **Account A (Attacker):** The one running the scan.
- **Account B (Victim):** The one you are trying to access.

**Extract Cookies:**
1. Log in to Account A in your browser.
2. Open DevTools (F12) -> Console.
3. Type `document.cookie` and copy the string.
4. Save it to a file `cookies.txt`.

### 2. Basic Scan
Scan a target using your imported cookies.

```bash
idor-scanner scan https://target.com \
  --cookies cookies.txt \
  --user1 "attacker" \
  --user2 "victim" \
  --ua-suffix "-BugBounty"
```

### 3. Bug Bounty Mode (Easiest)
Use pre-configured settings for popular programs.

```bash
# List available programs
idor-scanner bounty-list

# Scan using Inditex (Zara) rules
idor-scanner scan https://www.zara.com \
  --bounty inditex \
  --cookies cookies.txt \
  --user1 "me" --user2 "victim_id"
```

### 4. Pro Mode (Burp Suite)
Route traffic through Burp to see what's happening.

```bash
idor-scanner scan ... --proxy http://127.0.0.1:8080
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **403 Forbidden** | The tool automatically tries bypasses. If it fails, the endpoint is secure. |
| **429 Too Many Requests** | Reduce speed: `--rate-limit 2` |
| **Auth Fail** | Check if your cookies expired. Re-login and update `cookies.txt`. |
| **No Endpoints Found** | Use `--crawl` or provide an OpenAPI spec with `--openapi`. |

## Authentication Types

Specify auth type in credentials: `username:password:auth_type`

- `bearer` (default): Bearer token authentication
- `basic`: HTTP Basic authentication
- `cookie`: Cookie-based session
- `api_key`: API key authentication

```bash
idor-scanner scan https://api.example.com \
    --user1 "alice:password123:bearer" \
    --user2 "bob:password456:basic"
```

## Output Formats

```bash
# Terminal + JSON (default)
idor-scanner scan ... --format terminal --format json

# All formats
idor-scanner scan ... --format terminal --format json --format markdown --format html

# Save to specific directory
idor-scanner scan ... --output ./reports
```

## What It Detects

1. **Horizontal Privilege Escalation**: User A accessing User B's resources
2. **Vertical Privilege Escalation**: Regular user accessing admin resources
3. **HTTP Method Tampering**: GET blocked but POST/PUT/DELETE works
4. **Partial Data Leakage**: Similar responses indicating info disclosure

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Run IDOR vulnerability scan |
| `discover` | Discover API endpoints without scanning |
| `version` | Show version information |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Code formatting
black src/ tests/

# Linting
ruff check src/ tests/

# Type checking
mypy src/
```

## License

MIT License - See [LICENSE](LICENSE) for details.
