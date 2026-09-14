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
                  Security Vulnerability Detectors (Days 3-7)
    (Headers, Cookies, Info, Methods, CORS, Auth, SQLi, XSS, IDOR)
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
│   │   ├── idor.py          # IDORAccessControlDetector (Day 7: Cross-user object authorization)
│   │   ├── info_disclosure.py # ServerInfoDisclosureDetector (Version leakage)
│   │   ├── methods.py       # DangerousMethodsDetector (TRACE, OPTIONS, PUT, DELETE)
│   │   ├── sqli.py          # SQLInjectionDetector (Day 5: Error-based & Boolean differential)
│   │   └── xss.py           # XSSDetector (Day 6: Canary reflection & context encoding)
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
│       ├── db.py            # In-Memory SQLite Manager (Vulnerable vs Parameterized SQL)
│       └── __main__.py      # Independent launcher
├── tests/                   # Pytest automated test suite
├── setup.py                 # Package setup file
├── requirements.txt         # Project dependencies
└── README.md                # Platform documentation
```

---

## ✨ Vulnerability Detection Suite (Days 5, 6 & 7)

### Day 5 — SQL Injection Detection (`sqli_detector`)
- Detects Error-Based and Boolean-Based SQL Injection anomalies.
- Parameterized query fixes implemented in `target_app/db.py`.
- **Demo Command**: `python -m patchstack.cli --demo-sqli`

### Day 6 — XSS + Input Validation (`xss_detector`)
- Canary reflection discovery and context analysis (HTML/Attribute/Script).
- Detects Reflected & Stored XSS and missing HTML output encoding.
- Explains why context-aware encoding (`html.escape()`) is mandatory.
- **Demo Command**: `python -m patchstack.cli --demo-xss`

### Day 7 — IDOR + Access Control (`idor_detector`)
- Tests cross-account object access (e.g. User 101 attempting to fetch User 102 resource `/api/user/102`).
- Identifies Horizontal Privilege Escalation and Missing Authorization.
- **Demo Command**: `python -m patchstack.cli --demo-idor`

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

### 3. Run Vulnerability Audit Demos

```bash
# SQL Injection Lifecycle Demo
python -m patchstack.cli --demo-sqli

# XSS & Input Encoding Demo
python -m patchstack.cli --demo-xss

# IDOR & Authorization Audit Demo
python -m patchstack.cli --demo-idor

# Full Security Audit against target
python -m patchstack.cli --target http://127.0.0.1:5000
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
- [x] **Day 5**: SQL Injection detection (Error-based, Boolean-based, Parameterized query fixes).
- [x] **Day 6**: XSS & Input Validation (Canary reflection, Context analysis, HTML entity encoding).
- [x] **Day 7**: IDOR & Access Control Audit (Horizontal Privilege Escalation, Session Ownership Checks).
- [ ] **Day 8**: Proof-of-concept verification engine & false positive filtering.
- [ ] **Day 9**: Professional HTML & Executive PDF Report Exporter.
- [ ] **Day 10**: Benchmarking, documentation polish, and release engineering.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
