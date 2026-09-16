import os
import pytest
from patchstack.risk.engine import RiskEngine
from patchstack.detectors.base import Finding, Severity
from patchstack.reports.html_report import HTMLReportExporter
from patchstack.scanner.engine import ScanResult


def test_risk_engine_deduplication_and_mapping():
    raw_findings = [
        Finding(
            id="SQLI_ERROR_BASED",
            title="SQL Injection (Error-Based)",
            description="DB error",
            severity=Severity.CRITICAL,
            endpoint="http://127.0.0.1:5000/api/user",
            remediation="Use params",
            evidence="Parameter: id | Confidence: High | DB syntax error",
        ),
        Finding(
            id="SQLI_ERROR_BASED",
            title="SQL Injection (Error-Based)",
            description="DB error duplicate",
            severity=Severity.CRITICAL,
            endpoint="http://127.0.0.1:5000/api/user",
            remediation="Use params",
            evidence="Parameter: id | Confidence: High | DB syntax error",
        ),
        Finding(
            id="MISSING_CONTENT_SECURITY_POLICY",
            title="Missing CSP",
            description="Missing header",
            severity=Severity.MEDIUM,
            endpoint="http://127.0.0.1:5000/",
            remediation="Add CSP",
        ),
    ]

    deduped = RiskEngine.enrich_and_deduplicate(raw_findings)
    assert len(deduped) == 2

    # Check CWE & OWASP mappings
    sqli_f = [f for f in deduped if f.id == "SQLI_ERROR_BASED"][0]
    assert sqli_f.cwe == "CWE-89"
    assert sqli_f.owasp_category == "A03:2021-Injection"
    assert sqli_f.parameter == "id"


def test_risk_score_calculation():
    findings = [
        Finding(
            id="SQLI_ERROR_BASED",
            title="SQLi",
            description="",
            severity=Severity.CRITICAL,
            endpoint="/",
            remediation="",
        ),
        Finding(
            id="IDOR_HORIZONTAL",
            title="IDOR",
            description="",
            severity=Severity.HIGH,
            endpoint="/",
            remediation="",
        ),
    ]
    score = RiskEngine.calculate_risk_score(findings)
    assert 5.0 <= score <= 10.0


def test_html_report_exporter(tmp_path):
    output_file = tmp_path / "report.html"
    scan_result = ScanResult(
        target_url="http://127.0.0.1:5000",
        total_findings=1,
        findings=[
            Finding(
                id="SQLI_ERROR_BASED",
                title="SQL Injection",
                description="Test SQLi",
                severity=Severity.CRITICAL,
                endpoint="http://127.0.0.1:5000/user",
                remediation="Fix query",
                cwe="CWE-89",
                owasp_category="A03:2021-Injection",
            )
        ],
        risk_score=8.4,
        scan_duration_ms=10.0,
    )
    exporter = HTMLReportExporter()
    exported_path = exporter.export(scan_result, str(output_file))

    assert os.path.exists(exported_path)
    with open(exported_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "PatchStack Security Assessment Report" in content
    assert "SQL Injection" in content
    assert "8.4/10" in content
