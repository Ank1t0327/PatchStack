# 🏗️ PatchStack Architecture Specification

## Overview

**PatchStack** is a modular Web Application Security Assessment Platform designed with clean separation of concerns between reconnaissance, scanning, risk analysis, reporting, and dashboard visualization.

```
                                    PATCHSTACK PIPELINE
                                             │
                    ┌────────────────────────┴────────────────────────┐
                    │                                                 │
          Vulnerable Web App                                 Security Scanner
        (Flask Target Harness)                             (PatchStack Engine)
                    │                                                 │
                    └────────────────────────┬────────────────────────┘
                                             │
                                  HTTP Reconnaissance Engine
                               (Crawler, Parser, Fingerprinter)
                                             │
                                       HTTP Telemetry
                                             │
                                   Security Detectors Suite
                    (Headers, Cookies, Info Leak, Methods, CORS, Auth, SQLi, XSS, IDOR)
                                             │
                                  Vulnerability Findings
                                             │
                                        Risk Engine
                       (Deduplication, CWE/OWASP Mapping, 0-10 Score)
                                             │
                           ┌─────────────────┴─────────────────┐
                           │                                   │
                     SQLite Store                      Reporting Exporters
                    (patchstack.db)                     (JSON & HTML Reports)
                           │
                    Web Dashboard
                 (patchstack.dashboard)
```

## Component Architecture

### 1. HTTP Client & Telemetry Layer (`patchstack/scanner/http_client.py`)
- Wraps `requests.Session` with custom headers, User-Agent management, configurable timeouts, redirect tracking, and latency measurement in milliseconds.
- Captures `HTTPResponseTelemetry` objects detailing status code, raw response headers, cookie jars, body text, and timing.

### 2. HTTP Reconnaissance Engine (`patchstack/recon/`)
- `WebCrawler`: Domain-scoped recursive spider building an attack surface tree up to configurable depths.
- `HTMLReconParser`: Parses links (`<a href>`), forms (`<form action method>`), input fields (`<input name type required>`), scripts, and meta tags.
- `TechnologyFingerprinter`: Identifies server signatures (`Server`, `X-Powered-By`), framework cookies (`session`, `PHPSESSID`), and runtime environment.

### 3. Detector Suite (`patchstack/detectors/`)
- Abstract `BaseDetector` interface yielding standardized `Finding` models.
- **Detector Suite**:
  - `SecurityHeadersDetector`: Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
  - `CookieSecurityDetector`: Missing `HttpOnly`, `Secure`, and weak `SameSite` flags.
  - `ServerInfoDisclosureDetector`: Verbose version string leaks.
  - `DangerousMethodsDetector`: Enabled `TRACE`, `PUT`, `DELETE`, `OPTIONS` methods.
  - `CORSConfigDetector`: Arbitrary origin reflection with credentials.
  - `AuthSessionDetector`: Username enumeration, predictable session IDs, missing lockout/rate-limiting.
  - `SQLInjectionDetector`: Error-based & Boolean-based blind SQLi probes.
  - `XSSDetector`: Reflected & Stored XSS via canary reflection & context analysis.
  - `IDORAccessControlDetector`: Cross-user object authorization verification.

### 4. Risk Engine (`patchstack/risk/engine.py`)
- Performs finding deduplication on `(id, endpoint, parameter)`.
- Enriches findings with CWE codes and OWASP Top 10 (2021) categories.
- Calculates normalized target risk score (0.0 to 10.0 scale) based on severity weights and confidence levels.

### 5. Storage & Dashboard (`patchstack/storage/` & `patchstack/dashboard/`)
- `ScanDatabaseManager`: Persistent SQLite store (`patchstack.db`) recording scan history and findings.
- `create_dashboard_app`: Flask dashboard rendering terminal-style risk score cards, severity metrics, vulnerability inventory, and API endpoints.

### 6. Reporting Layer (`patchstack/reports/`)
- `JSONReportExporter`: Machine-readable JSON output export.
- `HTMLReportExporter`: Standalone executive HTML report exporter with dark mode CSS styling.
