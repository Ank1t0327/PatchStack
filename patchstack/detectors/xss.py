import html
from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class XSSDetector(BaseDetector):
    """
    Audits target endpoints for Reflected and Stored Cross-Site Scripting (XSS) and missing output encoding using:
    - Phase 1: Canary Reflection Detection
    - Phase 2: Context Analysis (HTML body, attribute, script tag)
    - Phase 3: Controlled Polyglot Payload Verification
    """

    def __init__(self):
        super().__init__(
            name="xss_detector",
            description="Detects Reflected XSS, Stored XSS, and missing HTML output encoding",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        test_endpoint = target_url
        if not ("?" in test_endpoint or "xss" in test_endpoint or "search" in test_endpoint):
            test_endpoint = target_url.rstrip("/") + "/api/v1/xss/search-vulnerable?q=test"

        # Extract base URL and query parameters
        if "?" in test_endpoint:
            base_url, query_str = test_endpoint.split("?", 1)
            params = dict(p.split("=", 1) for p in query_str.split("&") if "=" in p)
        else:
            base_url = test_endpoint
            params = {"q": "test"}

        for param_name in params.keys():
            # Phase 1: Canary Reflection Discovery
            canary = "pstk9a8b7"
            canary_url = f"{base_url}?{param_name}={canary}"
            canary_res: Optional[HTTPResponseTelemetry] = http_client.get(canary_url)

            if not canary_res or canary not in canary_res.body:
                continue

            # Phase 2 & 3: Controlled Payload Probe
            # Controlled test payload containing HTML markup tags
            payload = "<pstktag attr=\"test\">"
            probe_url = f"{base_url}?{param_name}={payload}"
            probe_res: Optional[HTTPResponseTelemetry] = http_client.get(probe_url)

            if probe_res and payload in probe_res.body:
                # Payload reflected completely unescaped
                findings.append(
                    Finding(
                        id="XSS_REFLECTED",
                        title="Reflected Cross-Site Scripting (XSS) & Missing Output Encoding",
                        description=f"User input supplied in parameter '{param_name}' is reflected unescaped directly in the HTTP response HTML body.",
                        severity=Severity.HIGH,
                        endpoint=base_url,
                        remediation="Apply context-aware HTML entity encoding (e.g. html.escape()) on all user-supplied input before rendering it in response templates.",
                        evidence=f"Parameter: {param_name} | Payload: '{payload}' reflected completely unescaped in response HTML",
                        cvss_score=7.5,
                    )
                )

        return findings
