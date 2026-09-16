import os
import pytest
from patchstack.storage.db import ScanDatabaseManager
from patchstack.dashboard.app import create_dashboard_app
from patchstack.scanner.engine import ScannerEngine, ScanResult
from patchstack.detectors.base import Finding, Severity


def test_scan_database_manager(tmp_path):
    db_file = str(tmp_path / "test_patchstack.db")
    db_manager = ScanDatabaseManager(db_file)

    scan_result = ScanResult(
        target_url="http://127.0.0.1:5000",
        total_findings=1,
        findings=[
            Finding(
                id="IDOR_HORIZONTAL",
                title="IDOR Vulnerability",
                description="Test IDOR",
                severity=Severity.HIGH,
                endpoint="http://127.0.0.1:5000/api/user/102",
                remediation="Add auth check",
                cwe="CWE-639",
                owasp_category="A01:2021-Broken Access Control",
            )
        ],
        risk_score=7.5,
        scan_duration_ms=15.0,
    )

    scan_id = db_manager.save_scan_result(scan_result)
    assert scan_id > 0

    latest = db_manager.get_latest_scan()
    assert latest is not None
    assert latest["target_url"] == "http://127.0.0.1:5000"
    assert latest["risk_score"] == 7.5


def test_dashboard_app(tmp_path):
    db_file = str(tmp_path / "test_dashboard.db")
    db_manager = ScanDatabaseManager(db_file)

    app = create_dashboard_app(db_file)
    client = app.test_client()

    # GET dashboard homepage
    res = client.get("/")
    assert res.status_code == 200
    assert "PATCHSTACK" in res.get_data(as_text=True)
