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
                              HTTP Analysis
                                    │
                            Detection Engine
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
│   ├── detectors/           # Security Detectors Framework
│   │   └── base.py          # BaseDetector interface & HeaderDetector
│   ├── reports/             # Report Generation Engine
│   │   └── base.py          # JSON / HTML report exporters
│   ├── scanner/             # Core Scanning Engine
│   │   ├── engine.py        # ScannerEngine orchestrator & risk calculator
│   │   └── http_client.py   # Telemetry-enabled HTTP client wrapper
│   └── target_app/          # Controlled Intentionally Vulnerable Web App
│       ├── app.py           # Flask app factory with security test routes
│       └── __main__.py      # Independent launcher
├── tests/                   # Pytest automated test suite
├── setup.py                 # Package setup file
├── requirements.txt         # Project dependencies
└── README.md                # Platform documentation
```

---

## ✨ Features (Day 1 Foundation)

- **Independent Dual Architecture**: The target web application (`target_app`) and the security scanner (`scanner`) operate as decoupled, independent systems.
- **Telemetry-Driven HTTP Engine**: Full response tracking (headers, status code, latency in ms, cookie telemetry).
- **Extensible Detector Plugin Model**: Abstract `BaseDetector` interface allowing clean addition of dynamic/static rule sets.
- **CVSS-Based Risk Scoring**: Aggregates finding severity and generates a cumulative risk score for the audit target.
- **Config & Logging Subsystems**: YAML configuration with environment variable overrides (`PATCHSTACK_TARGET`, `PATCHSTACK_TIMEOUT`, etc.) and structured log outputs.

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

### 3. Run the Security Scanner

Execute the scanner CLI against the target application:

```bash
# Basic scan against local target
python -m patchstack.cli --target http://127.0.0.1:5000

# JSON output export
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
- [ ] **Day 2**: Passive reconnaissance & crawling engine.
- [ ] **Day 3**: Security header & SSL/TLS misconfiguration detectors.
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
