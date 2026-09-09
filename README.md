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
                  Security Vulnerability Detectors (Day 3)
         (Headers, Cookies, Info Disclosure, Methods, CORS)
                                    │
                         Vulnerability Findings
                                    │
                              Risk Scoring
                                    │
                            Security Report
```

```
patchstack/
├── config/                  # Default YAML configs & env loader
│   └── default_config.yaml
├── patchstack/
│   ├── cli.py               # CLI Entry Point & Report Visualizer
│   ├── config.py            # ConfigManager & Dataclasses
│   ├── logger.py            # Structured Logger with Console/File handlers
│   ├── detectors/           # Security Detectors Framework (Day 3)
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
│       └── __main__.py      # Independent launcher
├── tests/                   # Pytest automated test suite
├── setup.py                 # Package setup file
├── requirements.txt         # Project dependencies
└── README.md                # Platform documentation
```

---

## ✨ Security Detectors (Day 3)

- **Security Headers Auditor**: Detects missing `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` (HSTS), `Referrer-Policy`, and `Permissions-Policy`.
- **Cookie Security Auditor**: Analyzes `Set-Cookie` headers for missing `HttpOnly`, missing `Secure`, and weak/missing `SameSite` flags.
- **Server Information Disclosure**: Identifies version leakage in `Server`, `X-Powered-By`, `X-AspNet-Version`, and runtime headers.
- **Dangerous HTTP Methods**: Checks for enabled `TRACE` (Cross-Site Tracing), `PUT`, `DELETE`, and `OPTIONS` method exposures.
- **CORS Misconfiguration Auditor**: Tests for arbitrary Origin reflection and wildcard origin permissions paired with `Access-Control-Allow-Credentials: true`.

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

### 3. Run the Security Scanner & Audit Suite

Execute the scanner CLI against the target application:

```bash
# Basic scan & security assessment against target
python -m patchstack.cli --target http://127.0.0.1:5000

# Sample CLI Output:
# Finding: Missing Content-Security-Policy
# Severity: Medium
# Endpoint: http://127.0.0.1:5000
# Evidence: Header not present
# Recommendation: Configure an appropriate Content-Security-Policy header (e.g., default-src 'self').

# JSON report export
python -m patchstack.cli --target http://127.0.0.1:5000 --json
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
- [ ] **Day 4**: Authentication & session security analysis.
- [ ] **Day 5**: Input validation & injection vulnerability checks (SQLi / XSS heuristics).
- [ ] **Day 6**: Access control & IDOR detection modules.
- [ ] **Day 7**: API security audit module (REST/JSON endpoints).
- [ ] **Day 8**: Proof-of-concept verification engine & false positive filtering.
- [ ] **Day 9**: Professional HTML & Executive PDF Report Exporter.
- [ ] **Day 10**: Benchmarking, documentation polish, and release engineering.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
