# 🛡️ PatchStack: Web Application Security Assessment Platform

> **PatchStack** is an automated, enterprise-grade Web Application Security Assessment Platform built to audit web applications, map attack surfaces, detect critical security vulnerabilities, validate findings with high confidence, compute normalized risk scores, and generate executive reporting.

---

## 📋 Problem Statement & Purpose

Modern web application security auditing requires more than static pattern matching or noisy scanners that dump unverified alerts. **PatchStack** bridges the gap between vulnerability discovery, threat context, and remediation engineering by offering:

1. **Automated Target Reconnaissance**: Deep HTTP spidering, form parameter extraction, header analysis, and stack fingerprinting.
2. **High-Confidence Vulnerability Auditing**: Active, context-aware probing for SQL Injection, Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), Broken Authentication, Weak Session Controls, Security Header misconfigurations, and CORS issues.
3. **Normalized Risk Engine**: Automated finding deduplication, OWASP Top 10 (2021) and CWE mapping, and composite 0–10 risk scoring.
4. **Vulnerability Lifecycle Verification**: Native support for **Vulnerable → Detect → Explain → Patch → Retest** workflow demonstrations to verify remediation efficacy.
5. **Interactive Dashboard & Executive Reporting**: Real-time terminal output, SQLite persistence, lightweight Flask web dashboard, and standalone executive HTML/JSON report exports.

---

## 📐 System Architecture

```
                                  PATCHSTACK ARCHITECTURE
                                              │
           ┌──────────────────────────────────┴──────────────────────────────────┐
           │                                                                     │
  Vulnerable Web App                                                     Security Scanner
  (Flask Benchmark Target)                                            (PatchStack CLI Engine)
           │                                                                     │
           └──────────────────────────────────┬──────────────────────────────────┘
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
           ┌──────────────────────────────────┴──────────────────────────────────┐
           │                                                                     │
     SQLite Storage                                                    Reporting Exporters
    (patchstack.db)                                                   (JSON & HTML Exporters)
           │
     Web Dashboard
  (patchstack.dashboard)
```

For detailed technical specifications, threat modeling, and audit methodology:
- 🏗️ [`docs/ARCHITECTURE.md`](file:///home/patch/Documents/projs/PatchStack/docs/ARCHITECTURE.md) — System Architecture & Component Interactions
- 🛡️ [`docs/THREAT_MODEL.md`](file:///home/patch/Documents/projs/PatchStack/docs/THREAT_MODEL.md) — Threat Landscape, STRIDE Modeling & Data Flow
- 🔬 [`docs/METHODOLOGY.md`](file:///home/patch/Documents/projs/PatchStack/docs/METHODOLOGY.md) — Detection Techniques, Payloads & Verification

---

## ✨ Feature Matrix

| Category | Capability Description | Engine Module | Standards Mapping |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | Domain-scoped web crawling, link discovery & form parameter mapping | `WebCrawler` & `HTMLReconParser` | N/A |
| **Fingerprinting** | HTTP headers analysis, cookie tracking & stack technology detection | `TechnologyFingerprinter` | N/A |
| **Configuration** | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, dangerous methods | `SecurityHeadersDetector` | **CWE-1021**, **A05:2021** |
| **Cookie Security** | Missing `HttpOnly`, `Secure`, or weak `SameSite` flags | `CookieSecurityDetector` | **CWE-614**, **A05:2021** |
| **Authentication** | Username enumeration, token predictability, missing rate-limiting | `AuthSessionDetector` | **CWE-287**, **A07:2021** |
| **SQL Injection** | Error-Based and Boolean-Based Blind SQL Injection auditing | `SQLInjectionDetector` | **CWE-89**, **A03:2021** |
| **Client-Side** | Reflected XSS, Stored XSS, missing context-aware HTML output encoding | `XSSDetector` | **CWE-79**, **A03:2021** |
| **Authorization** | IDOR, horizontal privilege escalation, session ownership checks | `IDORAccessControlDetector` | **CWE-639**, **A01:2021** |
| **Risk Engine** | Normalized 0-10 risk scoring, CVSS weighting & finding deduplication | `RiskEngine` | CVSS v3.1 Metrics |
| **Reporting** | Standalone executive HTML report & structured JSON exporters | `HTMLReportExporter` | Security Reports |
| **Dashboard** | Interactive web dashboard visualizer & terminal dashboard cards | `create_dashboard_app` | Executive UI |
| **Test Suite** | Comprehensive unit & resiliency test harness | `pytest` | QA / Verification |

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Ank1t0327/PatchStack.git
cd PatchStack

# Install dependencies and local package in editable mode
pip install -r requirements.txt
pip install -e .
```

### 2. Launch the Target Web Application

PatchStack includes an integrated, multi-mode Flask benchmark target for security testing:

```bash
python -m patchstack.target_app --port 5000
```

### 3. Run a Security Audit

Run an automated security scan against the target:

```bash
# Execute full security audit
python -m patchstack.cli --audit --target http://127.0.0.1:5000

# Generate standalone HTML security report
python -m patchstack.cli --audit --target http://127.0.0.1:5000 --html-report report.html
```

### 4. Launch the Web Dashboard

Start the web dashboard to visualize past scan runs, severity distributions, and vulnerability metrics:

```bash
python -m patchstack.dashboard --port 8080
```

Access the dashboard in your browser at `http://127.0.0.1:8080`.

---

## 🎬 Automated Demonstration Suites

PatchStack features CLI flags for automated before-and-after vulnerability lifecycle demonstrations:

```bash
# Full End-to-End Vulnerability Lifecycle Audit (Find -> Explain -> Patch -> Verify)
python -m patchstack.cli --demo-full

# SQL Injection Audit & Fix Verification
python -m patchstack.cli --demo-sqli

# Reflected & Stored XSS Audit & Fix Verification
python -m patchstack.cli --demo-xss

# IDOR & Broken Authorization Audit & Fix Verification
python -m patchstack.cli --demo-idor

# Authentication & Session Flaw Audit & Fix Verification
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

┌──────────────────────────────────────────────┐
│ PATCHSTACK DASHBOARD                         │
├──────────────────────────────────────────────┤
│ Overall Risk Score                 8.4 / 10  │
│                                              │
│ Critical Vulnerabilities           1         │
│ High Vulnerabilities               3         │
│ Medium Vulnerabilities             5         │
│ Low Vulnerabilities                2         │
├──────────────────────────────────────────────┤
│ Key Findings Summary                         │
│                                              │
│ SQL Injection                      CRITICAL  │
│ IDOR / Horizontal Escalation       HIGH      │
│ Reflected Cross-Site Scripting     HIGH      │
│ Insecure Cookie Configuration      MEDIUM    │
└──────────────────────────────────────────────┘
```

---

## 🧪 Automated Testing Suite

PatchStack features an automated test harness covering target endpoints, detectors, risk scoring, reporting engines, false positive validation, and server error resiliency:

```bash
pytest -v
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
