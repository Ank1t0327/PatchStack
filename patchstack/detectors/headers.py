from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class SecurityHeadersDetector(BaseDetector):
    """
    Analyzes HTTP response headers to identify missing or insecure security header controls.
    """

    def __init__(self):
        super().__init__(
            name="security_headers",
            description="Audits HTTP response headers for security defense mechanisms",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        res: Optional[HTTPResponseTelemetry] = http_client.get(target_url)

        if not res:
            return findings

        headers = {k.lower(): v for k, v in res.headers.items()}

        checks = [
            (
                "content-security-policy",
                "Missing Content-Security-Policy",
                "The HTTP response does not include Content-Security-Policy, exposing the application to Cross-Site Scripting (XSS) and data injection.",
                Severity.MEDIUM,
                "Configure an appropriate Content-Security-Policy header (e.g., default-src 'self').",
                6.5,
            ),
            (
                "x-frame-options",
                "Missing X-Frame-Options Header",
                "The application does not set X-Frame-Options, making it susceptible to Clickjacking framing attacks.",
                Severity.MEDIUM,
                "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
                4.3,
            ),
            (
                "x-content-type-options",
                "Missing X-Content-Type-Options Header",
                "The response lacks X-Content-Type-Options, allowing browsers to MIME-sniff response content.",
                Severity.LOW,
                "Set X-Content-Type-Options to 'nosniff'.",
                3.1,
            ),
            (
                "strict-transport-security",
                "Missing Strict-Transport-Security (HSTS)",
                "HTTP Strict Transport Security (HSTS) is missing, allowing potential downgrade attacks to unencrypted HTTP.",
                Severity.MEDIUM,
                "Enable HSTS header with max-age >= 31536000 and includeSubDomains.",
                5.3,
            ),
            (
                "referrer-policy",
                "Missing Referrer-Policy Header",
                "No Referrer-Policy header specified, potentially leaking sensitive URL query parameters to third-party sites.",
                Severity.LOW,
                "Set Referrer-Policy header to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                2.5,
            ),
            (
                "permissions-policy",
                "Missing Permissions-Policy Header",
                "Permissions-Policy is missing, allowing browser features (geolocation, camera, microphone) by default.",
                Severity.LOW,
                "Configure a restrictive Permissions-Policy header.",
                2.0,
            ),
        ]

        for header_key, title, desc, sev, rec, cvss in checks:
            if header_key not in headers:
                findings.append(
                    Finding(
                        id=f"MISSING_{header_key.upper().replace('-', '_')}",
                        title=title,
                        description=desc,
                        severity=sev,
                        endpoint=res.url,
                        remediation=rec,
                        evidence="Header not present",
                        cvss_score=cvss,
                    )
                )

        return findings
