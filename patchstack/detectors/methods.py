from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class DangerousMethodsDetector(BaseDetector):
    """
    Tests HTTP endpoints for dangerous or unsafe HTTP methods (TRACE, PUT, DELETE, OPTIONS).
    """

    def __init__(self):
        super().__init__(
            name="dangerous_methods",
            description="Detects unsafe HTTP methods enabled on target web endpoints",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Test 1: OPTIONS request to check Allow header
        options_res: Optional[HTTPResponseTelemetry] = http_client.request("OPTIONS", target_url)
        if options_res and options_res.status_code < 400:
            allow_header = options_res.headers.get("Allow", "") or options_res.headers.get("Access-Control-Allow-Methods", "")
            allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

            if "TRACE" in allowed_methods:
                findings.append(
                    Finding(
                        id="DANGEROUS_METHOD_TRACE_ENABLED",
                        title="Dangerous HTTP Method Enabled: TRACE",
                        description="The TRACE HTTP method is enabled on the server, exposing the application to Cross-Site Tracing (XST) attacks.",
                        severity=Severity.HIGH,
                        endpoint=target_url,
                        remediation="Disable HTTP TRACE method in web server configuration.",
                        evidence=f"Allow: {allow_header} (TRACE enabled)",
                        cvss_score=6.0,
                    )
                )

            for dangerous_method in ("PUT", "DELETE"):
                if dangerous_method in allowed_methods:
                    findings.append(
                        Finding(
                            id=f"DANGEROUS_METHOD_{dangerous_method}_ENABLED",
                            title=f"Potentially Unsafe HTTP Method Allowed: {dangerous_method}",
                            description=f"The HTTP response Allow header lists the '{dangerous_method}' method as allowed on endpoint '{target_url}'.",
                            severity=Severity.MEDIUM,
                            endpoint=target_url,
                            remediation=f"Restrict '{dangerous_method}' method access to authenticated and authorized requests only.",
                            evidence=f"Allow: {allow_header} ({dangerous_method} listed)",
                            cvss_score=4.0,
                        )
                    )

        # Test 2: Direct TRACE request test
        trace_res: Optional[HTTPResponseTelemetry] = http_client.request("TRACE", target_url)
        if trace_res and trace_res.status_code == 200 and "message/http" in trace_res.headers.get("Content-Type", "").lower():
            # Double check if not already reported
            if not any(f.id == "DANGEROUS_METHOD_TRACE_ENABLED" for f in findings):
                findings.append(
                    Finding(
                        id="DANGEROUS_METHOD_TRACE_ENABLED",
                        title="Dangerous HTTP Method Enabled: TRACE",
                        description="The TRACE method echoes back client headers in response body.",
                        severity=Severity.HIGH,
                        endpoint=target_url,
                        remediation="Disable TRACE method in web server.",
                        evidence="TRACE request returned HTTP 200 OK with echoed request headers",
                        cvss_score=6.0,
                    )
                )

        return findings
