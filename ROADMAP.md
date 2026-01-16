# Feature Roadmap

## Current Features (v1.0)
- [x] Horizontal IDOR Detection
- [x] Vertical Privilege Escalation
- [x] Unauthenticated Access Detection
- [x] HTTP Method Tampering
- [x] Automated 403 Bypass
- [x] HAR Traffic Import
- [x] Headless Browser Crawling
- [x] Burp Suite Proxy Integration
- [x] Auto-Exploit (curl) Generator
- [x] Bug Bounty Presets

## Planned Features (v2.0)

### High Priority
- [ ] **GraphQL Support**: Introspection, mutation fuzzing, batch query abuse
- [ ] **JWT Analysis**: Decode tokens, extract user IDs, test `alg:none`
- [ ] **Mass Assignment Detection**: Test adding extra fields to requests
- [ ] **API Versioning Bypass**: Test older API versions for weaker controls
- [ ] **Parameter Pollution**: Test `?id=1&id=2` style attacks

### Smart Detection
- [ ] **Semantic Field Analysis**: Automatically identify sensitive fields (email, ssn, password)
- [ ] **Response Fingerprinting**: Better diffing that ignores timestamps/nonces
- [ ] **Rate Limit Testing**: Detect and attempt bypass techniques
- [ ] **CORS Misconfiguration**: Test for overly permissive CORS policies

### Tooling
- [ ] **Subfinder Integration**: Auto-discover subdomains
- [ ] **Nuclei Templates**: Export findings as Nuclei templates
- [ ] **CI/CD Integration**: GitHub Actions, Jenkins support
- [ ] **Docker Image**: One-command deployment

### Reporting
- [ ] **SARIF Output**: For IDE integration
- [ ] **PDF Reports**: Professional pentest reports
- [ ] **Slack/Discord Notifications**: Real-time alerts

## Contributing
Want to help? Pick an item from the roadmap and submit a PR!
