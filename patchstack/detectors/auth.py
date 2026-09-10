import json
from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class AuthSessionDetector(BaseDetector):
    """
    Audits authentication endpoints and session management mechanisms for:
    - Username Enumeration
    - Predictable / Low-Entropy Session Tokens
    - Missing Account Lockout & Rate Limiting
    - Insecure Session Cookie Flags
    """

    def __init__(self):
        super().__init__(
            name="auth_session",
            description="Audits authentication controls, session entropy, username enumeration, and rate limiting",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Determine target auth endpoint path
        auth_endpoint = target_url
        if not auth_endpoint.endswith(("/login", "/login-vulnerable", "/login-secure", "/auth")):
            auth_endpoint = target_url.rstrip("/") + "/api/v1/auth/login-vulnerable"

        # --- Check 1: Username Enumeration ---
        resp_invalid = http_client.request(
            "POST",
            auth_endpoint,
            json={"username": "non_existent_user_99999", "password": "WrongPassword123!"},
        )
        resp_valid = http_client.request(
            "POST",
            auth_endpoint,
            json={"username": "admin", "password": "WrongPassword123!"},
        )

        if resp_invalid and resp_valid:
            invalid_text = resp_invalid.body.lower()
            valid_text = resp_valid.body.lower()

            if invalid_text != valid_text or resp_invalid.status_code != resp_valid.status_code:
                findings.append(
                    Finding(
                        id="AUTH_USERNAME_ENUMERATION",
                        title="Username Enumeration via Differential Authentication Responses",
                        description="The authentication endpoint returns different response messages or status codes for valid vs invalid usernames, allowing attackers to harvest valid user accounts.",
                        severity=Severity.HIGH,
                        endpoint=auth_endpoint,
                        remediation="Return uniform generic error messages (e.g., 'Invalid username or password') for all authentication failures.",
                        evidence=f"Invalid User Probe: '{resp_invalid.body.strip()}' vs Valid User Probe: '{resp_valid.body.strip()}'",
                        cvss_score=7.2,
                    )
                )

        # --- Check 2: Predictable Session Tokens & Cookie Security ---
        session_tokens: List[str] = []
        cookie_headers: List[str] = []

        # Login attempts to gather tokens
        for _ in range(3):
            login_resp = http_client.request(
                "POST",
                auth_endpoint,
                json={"username": "admin", "password": "AdminPassword123!"},
            )
            if login_resp and login_resp.status_code == 200:
                cookie_str = login_resp.headers.get("Set-Cookie", "")
                if cookie_str:
                    cookie_headers.append(cookie_str)
                    # Extract session_id token
                    for part in cookie_str.split(";"):
                        if "session_id=" in part:
                            token = part.split("=")[1].strip()
                            session_tokens.append(token)

        if len(session_tokens) >= 2:
            # Check sequential token pattern (e.g., SESSION-1001, SESSION-1002)
            is_sequential = False
            for t1, t2 in zip(session_tokens[:-1], session_tokens[1:]):
                if "SESSION-" in t1 and "SESSION-" in t2:
                    try:
                        num1 = int(t1.replace("SESSION-", ""))
                        num2 = int(t2.replace("SESSION-", ""))
                        if num2 - num1 == 1:
                            is_sequential = True
                    except ValueError:
                        pass

            if is_sequential:
                findings.append(
                    Finding(
                        id="AUTH_PREDICTABLE_SESSION_ID",
                        title="Predictable Sequential Session Tokens",
                        description="Session tokens follow a predictable sequential numeric pattern (e.g. SESSION-1001), allowing session hijacking attacks.",
                        severity=Severity.CRITICAL,
                        endpoint=auth_endpoint,
                        remediation="Use cryptographically secure, high-entropy random session identifiers (e.g. secrets.token_urlsafe(32)).",
                        evidence=f"Observed sequential tokens: {session_tokens}",
                        cvss_score=8.8,
                    )
                )

        # Audit session cookie flags
        if cookie_headers:
            sample_cookie = cookie_headers[0]
            cookie_parts_lower = [p.strip().lower() for p in sample_cookie.split(";")]
            has_httponly = any("httponly" in p for p in cookie_parts_lower)
            has_secure = any("secure" in p for p in cookie_parts_lower)
            has_samesite = any("samesite" in p for p in cookie_parts_lower)

            if not (has_httponly and has_secure and has_samesite):
                missing_flags = []
                if not has_httponly:
                    missing_flags.append("HttpOnly")
                if not has_secure:
                    missing_flags.append("Secure")
                if not has_samesite:
                    missing_flags.append("SameSite")

                findings.append(
                    Finding(
                        id="AUTH_INSECURE_SESSION_COOKIE",
                        title="Insecure Session Cookie Configuration",
                        description=f"Session cookies set during authentication lack essential defense flags ({', '.join(missing_flags)}).",
                        severity=Severity.HIGH,
                        endpoint=auth_endpoint,
                        remediation="Set HttpOnly, Secure, and SameSite=Strict on all session authentication cookies.",
                        evidence=f"Set-Cookie: {sample_cookie} (Missing: {', '.join(missing_flags)})",
                        cvss_score=6.5,
                    )
                )

        # --- Check 3: Missing Rate Limiting / Account Lockout ---
        burst_status_codes = []
        for _ in range(6):
            r = http_client.request(
                "POST",
                auth_endpoint,
                json={"username": "admin", "password": "BruteForceWrongPassword!"},
            )
            if r:
                burst_status_codes.append(r.status_code)

        # If all 6 attempts returned 401 and none returned 429 or lockout message
        if len(burst_status_codes) >= 6 and all(code == 401 for code in burst_status_codes):
            findings.append(
                Finding(
                    id="AUTH_MISSING_RATE_LIMITING",
                    title="Missing Account Lockout and Brute-Force Protection",
                    description="The authentication endpoint permits continuous failed login attempts without rate limiting (HTTP 429) or account lockout mechanisms.",
                    severity=Severity.HIGH,
                    endpoint=auth_endpoint,
                    remediation="Implement progressive delays, IP rate limiting, and temporary account lockout after 5 consecutive failed login attempts.",
                    evidence=f"Sent 6 consecutive failed logins -> All returned status code 401 without lockout or rate limit restriction.",
                    cvss_score=7.5,
                )
            )

        return findings
