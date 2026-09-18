# 🛡️ PatchStack: Web Application Security Assessment Platform

> **PatchStack** is an automated, modular Web Application Security Assessment Platform built to audit web applications, discover attack surfaces, detect critical security vulnerabilities, validate findings with high confidence, compute normalized risk scores, and generate executive reports.

---

## 📋 Problem Statement

Modern web security requires more than static rule matching or generic web scanners that report noise without context. **PatchStack** bridges the gap between threat discovery and remediation engineering by providing:
1. **Automated Target Reconnaissance**: Deep HTTP spidering, form parameter mapping, and stack fingerprinting.
2. **High-Confidence Vulnerability Auditing**: Active probing for SQLi, XSS, IDOR, Auth flaws, Header misconfigurations, and Session weaknesses.
3. **Full Vulnerability Lifecycle Verification**: Demonstrates the **Vulnerable → Detect → Explain → Fix → Retest** workflow to prove remediation efficacy.

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
                         Security Detectors Suite
     (Headers, Cookies, Info, Methods, CORS, Auth, SQLi, XSS, IDOR)
                                    │
                            Risk Engine Core
             (Deduplication, CWE & OWASP Mappings, 0-10 Risk Score)
                                    │
           ┌────────────────────────┴────────────────────────┐
           │                                                 │
     SQLite Storage                                  Reporting Exporters
    (patchstack.db)                                 (JSON & HTML Exporters)
           │
     Web Dashboard
  (patchstack.dashboard)
```

For detailed technical specifications, see [`docs/ARCHITECTURE.md`](file:///home/patch/Documents/projs/PatchStack/docs/ARCHITECTURE.md) and [`docs/THREAT_MODEL.md`](file:///home/patch/Documents/projs/PatchStack/docs/THREAT_MODEL.md).

---

## ✨ Core Feature Matrix

| Security Area | Feature Description | Detector Module | Standards Mapping |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | Domain-scoped spidering, link & form parameter discovery | `WebCrawler` & `HTMLReconParser` | N/A |
| **HTTP Analysis** | Latency, headers, cookies, and framework stack fingerprinting | `TechnologyFingerprinter` | N/A |
| **Configuration** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options | `SecurityHeadersDetector` | CWE-1021, A05:2021 |
| **Sessions** | Missing `HttpOnly`, `Secure`, and weak `SameSite` flags | `CookieSecurityDetector` | CWE-614, A05:2021 |
| **Authentication** | Username enumeration, predictable tokens, rate-limiting | `AuthSessionDetector` | CWE-287 / CWE-307, A07:2021 |
| **Injection** | Error-Based and Boolean-Based Blind SQL Injection | `SQLInjectionDetector` | **CWE-89**, **A03:2021** |
| **Client-Side** | Reflected XSS, Stored XSS, missing HTML output encoding | `XSSDetector` | **CWE-79**, **A03:2021** |
| **Authorization** | IDOR, horizontal privilege escalation, session ownership | `IDORAccessControlDetector` | **CWE-639**, **A01:2021** |
| **Risk Engine** | Normalized 0-10 risk scoring & finding deduplication | `RiskEngine` | CVSS v3.1 Metrics |
| **Reporting** | Standalone executive HTML report & raw JSON exports | `HTMLReportExporter` | Exec Reports |
| **Dashboard** | Web dashboard visualizer & terminal risk cards | `create_dashboard_app` | Dashboard UI |
| **Testing** | Resiliency test suite (false positives, timeouts, 500s) | `pytest` | Test Harness |

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

### 2. Launch the Target Web Application

In a separate terminal, launch the target application testbed:

```bash
python -m patchstack.target_app --port 5000
```

### 3. Run the Full Security Assessment Pipeline

Execute the end-to-end single-command security audit:

```bash
# Single-command full audit
python -m patchstack.cli --audit --target http://127.0.0.1:5000

# Launch interactive Web Dashboard
python -m patchstack.dashboard --port 8080
```

---

## 🎬 Live Demonstration Commands

Run PatchStack's before-and-after audit lifecycle demonstrations:

```bash
# Ultimate Before -> After Audit Lifecycle Demo (Find -> Patch -> Vulnerabilities Disappear!)
python -m patchstack.cli --demo-full

# SQL Injection Lifecycle Demo
python -m patchstack.cli --demo-sqli

# XSS & Input Validation Demo
python -m patchstack.cli --demo-xss

# IDOR & Authorization Audit Demo
python -m patchstack.cli --demo-idor

# Auth & Session Security Demo
python -m patchstack.cli --demo-auth
```

---

## 📊 Sample Terminal Output

```
 PATCHSTACK SECURITY REPORT

 Target: http://127.0.0.1:5000

 Critical   1
 High       3
 Medium     5
 Low        2

 Risk Score: 8.4/10

┌─────────────────────────────────┐
│ PATCHSTACK                      │
├─────────────────────────────────┤
│ Risk Score             8.4   /10   │
│                                 │
│ Critical      1                 │
│ High          3                 │
│ Medium        5                 │
│ Low           2                 │
├─────────────────────────────────┤
│ Vulnerabilities                 │
│                                 │
│ SQL Injection      CRITICAL  │
│ IDOR               HIGH      │
│ Reflected Cross-Si HIGH      │
│ Insecure Cookie Fl MEDIUM    │
└─────────────────────────────────┘
```

---

## 🧪 Automated Testing Suite

Run the 10-day comprehensive test suite (30+ unit tests):

```bash
pytest -v
```

---

## 📅 10-Day Implementation Roadmap

- [x] **Day 1**: Foundation & modular architecture (Config, Logging, Flask Target App, Scanner Core).
- [x] **Day 2**: HTTP Reconnaissance engine (Spider, Form Parser, Cookie Tracking, Technology Stack Fingerprinter).
- [x] **Day 3**: Security headers, cookie security, server info disclosure, dangerous methods, and CORS detectors.
- [x] **Day 4**: Authentication & session security analysis (Vulnerable vs Secure Auth, Username Enum, Token Predictability, Lockout).
- [x] **Day 5**: SQL Injection detection (Error-based, Boolean-based, Parameterized query fixes).
- [x] **Day 6**: XSS & Input Validation (Canary reflection, Context analysis, HTML entity encoding).
- [x] **Day 7**: IDOR & Access Control Audit (Horizontal Privilege Escalation, Session Ownership Checks).
- [x] **Day 8**: Risk Engine (Deduplication, CWE & OWASP Mappings, 0-10 Risk Score) & Standalone HTML Exporter.
- [x] **Day 9**: SQLite Storage, Flask Web Dashboard (`patchstack.dashboard`), and Single-Command Assessment Pipeline.
- [x] **Day 10**: Testing Resiliency Suite (False Positives/Negatives, Timeouts, 500s), Comprehensive Documentation (`docs/`), and Full Lifecycle Demo.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
