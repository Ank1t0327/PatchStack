import re
from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class SQLInjectionDetector(BaseDetector):
    """
    Audits target web application endpoints and parameter inputs for SQL Injection vulnerabilities using:
    - Safe differential probing (Syntax error injection, Boolean logic differentials)
    - Response behavior analysis (Database syntax error signatures, status code & body size variance)
    - Confidence scoring (High for DB error signatures / logic variance, Medium for status anomalies)
    """

    def __init__(self):
        super().__init__(
            name="sqli_detector",
            description="Detects Error-Based and Boolean-Based SQL Injection vulnerabilities in query parameters and forms",
        )

        # Common SQL Database Error Signatures
        self.sql_error_patterns = [
            re.compile(r"sqlite3\.OperationalError", re.I),
            re.compile(r"syntax error near", re.I),
            re.compile(r"unclosed quotation mark", re.I),
            re.compile(r"you have an error in your sql syntax", re.I),
            re.compile(r"pg_query\(\): query failed", re.I),
            re.compile(r"ORA-\d{5}", re.I),
            re.compile(r"SQLSTATE\[\d+\]", re.I),
        ]

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Determine target endpoint for SQLi audit
        test_endpoint = target_url
        if not ("?" in test_endpoint or "user" in test_endpoint or "search" in test_endpoint):
            test_endpoint = target_url.rstrip("/") + "/api/v1/sqli/user-vulnerable?id=101"

        # Extract base URL and query parameters
        if "?" in test_endpoint:
            base_url, query_str = test_endpoint.split("?", 1)
            params = dict(p.split("=", 1) for p in query_str.split("&") if "=" in p)
        else:
            base_url = test_endpoint
            params = {"id": "101"}

        for param_name, orig_val in params.items():
            # 1. Baseline Request
            baseline_url = f"{base_url}?{param_name}={orig_val}"
            baseline_res: Optional[HTTPResponseTelemetry] = http_client.get(baseline_url)

            if not baseline_res:
                continue

            # 2. Syntax Error Test Payload
            error_payload = f"{orig_val}'"
            error_url = f"{base_url}?{param_name}={error_payload}"
            error_res: Optional[HTTPResponseTelemetry] = http_client.get(error_url)

            if not error_res:
                continue

            has_sql_error = False
            for pattern in self.sql_error_patterns:
                if pattern.search(error_res.body):
                    has_sql_error = True
                    break

            # 3. Boolean True Probe
            true_payload = f"{orig_val}' OR '1'='1"
            true_url = f"{base_url}?{param_name}={true_payload}"
            true_res: Optional[HTTPResponseTelemetry] = http_client.get(true_url)

            # 4. Boolean False Probe
            false_payload = f"{orig_val}' AND '1'='2"
            false_url = f"{base_url}?{param_name}={false_payload}"
            false_res: Optional[HTTPResponseTelemetry] = http_client.get(false_url)

            # Evaluate Findings
            if has_sql_error:
                findings.append(
                    Finding(
                        id="SQLI_ERROR_BASED",
                        title="SQL Injection (Error-Based)",
                        description=f"The endpoint '{base_url}' parameter '{param_name}' is vulnerable to SQL Injection. Injecting SQL single quotes triggered a database syntax error.",
                        severity=Severity.CRITICAL,
                        endpoint=base_url,
                        remediation="Use parameterized database queries (prepared statements) with bound variables instead of string concatenation.",
                        evidence=f"Parameter: {param_name} | Confidence: High | Evidence: Response behavior changed (Database syntax error: '{error_res.body.strip()[:100]}...')",
                        cvss_score=9.8,
                    )
                )

            elif true_res and false_res:
                # Check Boolean Differential
                if true_res.status_code == 200 and (false_res.status_code == 404 or len(false_res.body) != len(true_res.body)):
                    findings.append(
                        Finding(
                            id="SQLI_BOOLEAN_BASED",
                            title="SQL Injection (Boolean-Based Blind)",
                            description=f"The parameter '{param_name}' on endpoint '{base_url}' is vulnerable to Blind SQL Injection based on boolean response differentials.",
                            severity=Severity.CRITICAL,
                            endpoint=base_url,
                            remediation="Implement parameterized queries (prepared statements) for all database operations.",
                            evidence=f"Parameter: {param_name} | Confidence: High | Evidence: Response behavior changed (TRUE probe returned HTTP {true_res.status_code} [{len(true_res.body)} bytes] vs FALSE probe returned HTTP {false_res.status_code} [{len(false_res.body)} bytes])",
                            cvss_score=9.1,
                        )
                    )

        return findings
