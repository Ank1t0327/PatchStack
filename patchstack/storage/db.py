import json
import sqlite3
import os
from typing import Dict, Any, List, Optional


class ScanDatabaseManager:
    """
    Manages persistent SQLite storage (`patchstack.db`) for scan history, telemetry, and vulnerability findings.
    """

    def __init__(self, db_path: str = "patchstack.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT,
                risk_score REAL,
                total_findings INTEGER,
                duration_ms REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                raw_json TEXT
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                finding_id TEXT,
                title TEXT,
                severity TEXT,
                confidence TEXT,
                endpoint TEXT,
                parameter TEXT,
                cwe TEXT,
                owasp_category TEXT,
                evidence TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
            """
        )
        conn.commit()
        conn.close()

    def save_scan_result(self, scan_result: Any) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        data = scan_result.to_dict()

        cursor.execute(
            """
            INSERT INTO scans (target_url, risk_score, total_findings, duration_ms, raw_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_result.target_url,
                scan_result.risk_score,
                scan_result.total_findings,
                scan_result.scan_duration_ms,
                json.dumps(data),
            ),
        )
        scan_id = cursor.lastrowid

        for f in scan_result.findings:
            cursor.execute(
                """
                INSERT INTO findings (scan_id, finding_id, title, severity, confidence, endpoint, parameter, cwe, owasp_category, evidence, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    f.id,
                    f.title,
                    f.severity.value,
                    f.confidence,
                    f.endpoint,
                    f.parameter or "",
                    f.cwe,
                    f.owasp_category,
                    f.evidence,
                    f.remediation,
                ),
            )

        conn.commit()
        conn.close()
        return scan_id

    def get_latest_scan(self) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        scan_dict = dict(row)
        if scan_dict.get("raw_json"):
            scan_dict["details"] = json.loads(scan_dict["raw_json"])
        return scan_dict
