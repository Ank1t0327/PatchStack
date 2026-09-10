# 🛡️ PatchStack: Web Security Assessment Platform

> **PatchStack** is a modular, high-performance Web Application Security Assessment Platform designed to audit web applications, detect common security misconfigurations & vulnerabilities, validate findings, and generate actionable security engineering reports.

---

## 📐 Architecture Overview

```
                        PATCHSTACK ARCHITECTURE
                                    │
           ┌────────────────────────┴────────────────────────┐
           │                                                 │
  Vulnerable Web App                                 Security Scanner
  (Flask Test Target)                              (PatchStack Engine)
           │                                                 │
           └────────────────────────┬────────────────────────┘
                                    │
                         HTTP Reconnaissance Engine
                       (Crawler, Parser, Fingerprinter)
                                    │
                              HTTP Analysis
                                    │
                  Security Vulnerability Detectors (Day 3 & 4)
   (Headers, Cookies, Info Leak, Methods, CORS, Auth & Session)
                                    │
                         Vulnerability Findings
                                    │
               Vulnerable → Detect → Explain → Fix → Retest
                                    │
                            Security Report
```

```
patchstack/
├── config/                  # Default YAML configs & env loader
│   └── default_config.yaml
├── patchstack/
│   ├── cli.py               # CLI Entry Point & Comparative Retest Visualizer
│   ├── config.py            # ConfigManager & Dataclasses
│   ├── logger.py            # Structured Logger with Console/File handlers
│   ├── detectors/           # Security Detectors Framework
│   │   ├── auth.py          # AuthSessionDetector (Day 4: Enum, Session Entropy, Lockout, Cookies)
│   │   ├── base.py          # BaseDetector interface & Finding models
│   │   ├── cookies.py       # CookieSecurityDetector (HttpOnly, Secure, SameSite)
│   │   ├── cors.py          # CORSConfigDetector (Origin reflection & credentials)
│   │   ├── headers.py       # SecurityHeadersDetector (CSP, HSTS, X-Frame-Options)
│   │   ├── info_disclosure.py # ServerInfoDisclosureDetector (Version leakage)
│   │   └── methods.py       # DangerousMethodsDetector (TRACE, OPTIONS, PUT, DELETE)
│   ├── recon/               # HTTP Reconnaissance Engine (Day 2)
│   │   ├── crawler.py       # Domain-scoped recursive WebCrawler
│   │   ├── engine.py        # ReconEngine orchestrator
│   │   ├── fingerprint.py   # TechnologyFingerprinter (Server, Framework, Stack)
│   │   ├── models.py        # DiscoveredEndpoint, Form, Cookie & Fingerprint models
│   │   └── parser.py        # HTMLReconParser for links, forms, scripts, meta tags
│   ├── reports/             # Report Generation Engine
│   │   └── base.py          # JSON / HTML report exporters
│   ├── scanner/             # Core Scanning Engine
│   │   ├── engine.py        # ScannerEngine orchestrator & risk calculator
│   │   └── http_client.py   # Telemetry-enabled HTTP client wrapper
│   └── target_app/          # Controlled Intentionally Vulnerable Web App
│       ├── app.py           # Flask app factory with enriched HTML routes & test harnesses
│       ├── auth.py          # Dual Auth System: VulnerableAuthManager vs SecureAuthManager
│       └── __main__.py      # Independent launcher
├── tests/                   # Pytest automated test suite
├── setup.py                 # Package setup file
├── requirements.txt         # Project dependencies
└── README.md                # Platform documentation
```

---

## ✨ Authentication & Session Security (Day 4)

PatchStack features a dual-mode authentication harness for live comparative security auditing:
- **Vulnerable Auth (`/api/v1/auth/login-vulnerable`)**: Demonstrates username enumeration (`"User not found"` vs `"Incorrect password"`), predictable sequential session tokens (`SESSION-1001`), missing account lockout/rate-limiting, and weak session cookies.
- **Secure Remediation (`/api/v1/auth/login-secure`)**: Implements generic error messages (`"Invalid credentials"`), high-entropy random tokens (`secrets.token_urlsafe(32)`), 15-minute account lockout after 5 failed attempts, and `HttpOnly; Secure; SameSite=Strict` cookies.
- **Vulnerable → Detect → Explain → Fix → Retest Workflow**: Run `python -m patchstack.cli --demo-auth` to execute an automated side-by-side comparative retest.

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Ank1t0327/PatchStack.git
cd PatchStack

# Install dependencies and local package
pip install -r requirements.txt
pip install -e .
```

### 2. Start the Target Web Application

Launch the controlled vulnerable web server in a separate terminal:

```bash
python -m patchstack.target_app --port 5000
```

### 3. Run the Authentication & Session Security Demo

Execute the CLI demo workflow comparing vulnerable vs secure auth implementations:

```bash
python -m patchstack.cli --target http://127.0.0.1:5000 --demo-auth
```

---

## 🧪 Running Tests

Validate system integrity using `pytest`:

```bash
pytest -v
```

---

## 📅 10-Day Development Roadmap

- [x] **Day 1**: Repository foundation, architecture design, target application skeleton, scanner core, logging & config system.
- [x] **Day 2**: HTTP Reconnaissance engine (web crawler, form parser, cookie tracking, technology stack fingerprinter).
- [x] **Day 3**: Security headers, cookie security, server info disclosure, dangerous methods, and CORS detectors.
- [x] **Day 4**: Authentication & session security analysis (Vulnerable vs Secure Auth, Username Enum, Token Predictability, Rate Limiting, Cookie Flags, Comparative Retest).
- [ ] **Day 5**: Input validation & injection vulnerability checks (SQLi / XSS heuristics).
- [ ] **Day 6**: Access control & IDOR detection modules.
- [ ] **Day 7**: API security audit module (REST/JSON endpoints).
- [ ] **Day 8**: Proof-of-concept verification engine & false positive filtering.
- [ ] **Day 9**: Professional HTML & Executive PDF Report Exporter.
- [ ] **Day 10**: Benchmarking, documentation polish, and release engineering.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
