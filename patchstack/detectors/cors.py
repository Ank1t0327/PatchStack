from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class CORSConfigDetector(BaseDetector):
    """
    Audits Cross-Origin Resource Sharing (CORS) configurations for dangerous origin reflection and credential exposure.
    """

    def __init__(self):
        super().__init__(
            name="cors_misconfig",
            description="Detects permissive or insecure CORS origin reflection and credential settings",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        test_origin = "http://evil-attacker-domain.com"
        res: Optional[HTTPResponseTelemetry] = http_client.get(
            target_url,
            headers={"Origin": test_origin},
        )

        if not res:
            return findings

        headers = {k.lower(): v for k, v in res.headers.items()}
        allow_origin = headers.get("access-control-allow-origin")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"

        # Check 1: Arbitrary Origin Reflection + Credentials True
        if allow_origin == test_origin and allow_credentials:
            findings.append(
                Finding(
                    id="CORS_ARBITRARY_ORIGIN_REFLECTED_WITH_CREDENTIALS",
                    title="CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
                    description="The target reflects arbitrary untrusted Origin headers in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials to true. This permits cross-origin theft of authenticated session data.",
                    severity=Severity.HIGH,
                    endpoint=target_url,
                    remediation="Validate Origin against a strict whitelist of trusted domain names rather than reflecting incoming Origin headers.",
                    evidence=f"Origin: {test_origin} -> Access-Control-Allow-Origin: {allow_origin}, Access-Control-Allow-Credentials: true",
                    cvss_score=7.5,
                )
            )

        # Check 2: Null Origin Reflected + Credentials True
        elif allow_origin == test_origin and not allow_credentials:
            findings.append(
                Finding(
                    id="CORS_ARBITRARY_ORIGIN_REFLECTED",
                    title="CORS Misconfiguration: Arbitrary Origin Reflection",
                    description="The server reflects arbitrary Origin headers in Access-Control-Allow-Origin, allowing unauthenticated cross-origin requests.",
                    severity=Severity.MEDIUM,
                    endpoint=target_url,
                    remediation="Configure a restrictive CORS policy specifying allowed origins explicitly.",
                    evidence=f"Origin: {test_origin} -> Access-Control-Allow-Origin: {allow_origin}",
                    cvss_score=5.0,
                )
            )

        # Check 3: Wildcard Origin * with Credentials
        if allow_origin == "*" and allow_credentials:
            findings.append(
                Finding(
                    id="CORS_WILDCARD_WITH_CREDENTIALS",
                    title="CORS Misconfiguration: Wildcard Origin with Credentials",
                    description="The server specifies Access-Control-Allow-Origin: * while allowing credentials, violating CORS specification and exposing data.",
                    severity=Severity.HIGH,
                    endpoint=target_url,
                    remediation="Do not combine wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.",
                    evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    cvss_score=7.0,
                )
            )

        # Test 'null' origin
        res_null: Optional[HTTPResponseTelemetry] = http_client.get(
            target_url,
            headers={"Origin": "null"},
        )
        if res_null:
            null_headers = {k.lower(): v for k, v in res_null.headers.items()}
            null_origin = null_headers.get("access-control-allow-origin")
            null_credentials = null_headers.get("access-control-allow-credentials", "").lower() == "true"

            if null_origin == "null" and null_credentials:
                findings.append(
                    Finding(
                        id="CORS_NULL_ORIGIN_ALLOWED",
                        title="CORS Misconfiguration: Trusting Null Origin",
                        description="The server trusts 'null' Origin headers with credentials, allowing sandboxed iframe exploits.",
                        severity=Severity.MEDIUM,
                        endpoint=target_url,
                        remediation="Do not trust 'null' as a valid CORS origin.",
                        evidence="Origin: null -> Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true",
                        cvss_score=5.5,
                    )
                )

        return findings
