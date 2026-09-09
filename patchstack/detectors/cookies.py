from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class CookieSecurityDetector(BaseDetector):
    """
    Inspects Set-Cookie headers for missing HttpOnly, Secure, and SameSite attributes.
    """

    def __init__(self):
        super().__init__(
            name="cookie_security",
            description="Audits cookie flags (HttpOnly, Secure, SameSite) for session security",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        res: Optional[HTTPResponseTelemetry] = http_client.get(target_url)

        if not res:
            return findings

        # Extract all Set-Cookie raw header strings from HTTP response telemetry
        raw_headers = res.headers
        set_cookie_headers = []
        for k, v in raw_headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        if not set_cookie_headers:
            return findings

        for cookie_str in set_cookie_headers:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            if not cookie_parts:
                continue

            cookie_name = cookie_parts[0].split("=")[0]
            cookie_flags_lower = [p.lower() for p in cookie_parts[1:]]

            has_httponly = any("httponly" in flag for flag in cookie_flags_lower)
            has_secure = any("secure" in flag for flag in cookie_flags_lower)
            samesite_val = None
            for flag in cookie_flags_lower:
                if flag.startswith("samesite="):
                    samesite_val = flag.split("=")[1].strip()

            # Check 1: Missing HttpOnly
            if not has_httponly:
                findings.append(
                    Finding(
                        id="COOKIE_MISSING_HTTPONLY",
                        title=f"Insecure Cookie Flag: Missing HttpOnly ({cookie_name})",
                        description=f"The cookie '{cookie_name}' is set without the HttpOnly flag, allowing client-side scripts to access it via document.cookie.",
                        severity=Severity.MEDIUM,
                        endpoint=res.url,
                        remediation=f"Set the HttpOnly flag on the '{cookie_name}' cookie to mitigate XSS-based cookie theft.",
                        evidence=f"Set-Cookie: {cookie_str} (HttpOnly missing)",
                        cvss_score=5.0,
                    )
                )

            # Check 2: Missing Secure
            if not has_secure:
                findings.append(
                    Finding(
                        id="COOKIE_MISSING_SECURE",
                        title=f"Insecure Cookie Flag: Missing Secure ({cookie_name})",
                        description=f"The cookie '{cookie_name}' lacks the Secure attribute, risking transmission over unencrypted HTTP channels.",
                        severity=Severity.MEDIUM,
                        endpoint=res.url,
                        remediation=f"Set the Secure attribute on the '{cookie_name}' cookie.",
                        evidence=f"Set-Cookie: {cookie_str} (Secure missing)",
                        cvss_score=4.5,
                    )
                )

            # Check 3: Missing or weak SameSite
            if not samesite_val or samesite_val not in ("strict", "lax"):
                evidence_text = (
                    f"Set-Cookie: {cookie_str} (SameSite missing)"
                    if not samesite_val
                    else f"Set-Cookie: {cookie_str} (SameSite={samesite_val})"
                )
                findings.append(
                    Finding(
                        id="COOKIE_WEAK_SAMESITE",
                        title=f"Insecure Cookie Flag: Missing or Weak SameSite ({cookie_name})",
                        description=f"The cookie '{cookie_name}' does not specify a strict SameSite attribute (Strict or Lax), increasing CSRF vulnerability.",
                        severity=Severity.LOW,
                        endpoint=res.url,
                        remediation=f"Set SameSite=Lax or SameSite=Strict on the '{cookie_name}' cookie.",
                        evidence=evidence_text,
                        cvss_score=3.5,
                    )
                )

        return findings
