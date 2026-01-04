# 📘 CrossCheck (IDOR Scanner) - User Manual

## 🚀 Quick Start Guide

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

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| **403 Forbidden** | The tool automatically tries bypasses. If it fails, the endpoint is secure. |
| **429 Too Many Requests** | Reduce speed: `--rate-limit 2` |
| **Auth Fail** | Check if your cookies expired. Re-login and update `cookies.txt`. |
| **No Endpoints Found** | Use `--crawl` or provide an OpenAPI spec with `--openapi`. |

---

## 📦 Installation for New Users

```bash
git clone https://github.com/ruwithma/crosscheck.git
cd crosscheck
pip install -e .
```
