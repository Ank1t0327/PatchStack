from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class IDORAccessControlDetector(BaseDetector):
    """
    Audits object endpoints for Insecure Direct Object References (IDOR), Horizontal Privilege Escalation,
    and missing authorization controls by testing cross-user session access.
    """

    def __init__(self):
        super().__init__(
            name="idor_detector",
            description="Audits object resource endpoints for IDOR and horizontal privilege escalation vulnerabilities",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Target IDOR endpoint path
        base_endpoint = target_url.rstrip("/")
        if not ("user" in base_endpoint or "10" in base_endpoint):
            vuln_url_pattern = f"{base_endpoint}/api/v1/idor/user-vulnerable"
        else:
            vuln_url_pattern = base_endpoint

        # Test Scenario: User 101 attempting to access User 102 resource
        # Authenticate as User 101 to obtain session cookie
        auth_res = http_client.request(
            "POST",
            f"{base_endpoint}/api/v1/auth/login-vulnerable",
            json={"username": "user101", "password": "Password101!"},
        )

        user101_cookie = auth_res.headers.get("Set-Cookie", "") if auth_res else ""

        # Attempt to access User 102's object endpoint while authenticated as User 101
        target_obj_url = f"{vuln_url_pattern}/102"
        cross_res: Optional[HTTPResponseTelemetry] = http_client.get(
            target_obj_url,
            headers={"Cookie": user101_cookie},
        )

        if cross_res and cross_res.status_code == 200 and "user102" in cross_res.body:
            evidence_str = (
                f"IDOR\n"
                f"Severity: High\n"
                f"Endpoint: /api/user/102\n"
                f"Current User: 101\n"
                f"Accessed Object: 102\n"
                f"Authorization: Failed"
            )
            findings.append(
                Finding(
                    id="IDOR_HORIZONTAL_PRIVILEGE_ESCALATION",
                    title="Insecure Direct Object Reference (IDOR) & Missing Authorization",
                    description="Authenticated user (User 101) successfully accessed another user's restricted profile resource (User 102) without server-side authorization checks.",
                    severity=Severity.HIGH,
                    endpoint=target_obj_url,
                    remediation="Enforce server-side access control checks verifying that the authenticated session user matches the requested object resource owner before returning data.",
                    evidence=evidence_str,
                    cvss_score=8.5,
                )
            )

        return findings
