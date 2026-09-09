import re
from typing import List, Optional
from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class ServerInfoDisclosureDetector(BaseDetector):
    """
    Identifies server information leakage via HTTP response headers and technology version strings.
    """

    def __init__(self):
        super().__init__(
            name="info_disclosure",
            description="Detects verbose server version disclosure in HTTP headers and response bodies",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        res: Optional[HTTPResponseTelemetry] = http_client.get(target_url)

        if not res:
            return findings

        headers = {k.lower(): v for k, v in res.headers.items()}

        # Check Server header
        if "server" in headers:
            server_val = headers["server"]
            # Check for version pattern like Flask/3.0.0, Apache/2.4.41, nginx/1.18.0
            if re.search(r"[/v]\d+\.\d+", server_val, re.IGNORECASE):
                findings.append(
                    Finding(
                        id="SERVER_INFO_DISCLOSURE_SERVER_HEADER",
                        title="Server Information Disclosure via Server Header",
                        description=f"The Server header reveals detailed software version details: '{server_val}'. Attackers can leverage specific version information to target known vulnerabilities.",
                        severity=Severity.LOW,
                        endpoint=res.url,
                        remediation="Configure web server to suppress or obfuscate the Server header.",
                        evidence=f"Server: {server_val}",
                        cvss_score=3.0,
                    )
                )

        # Check X-Powered-By header
        if "x-powered-by" in headers:
            x_powered = headers["x-powered-by"]
            findings.append(
                Finding(
                    id="SERVER_INFO_DISCLOSURE_X_POWERED_BY",
                    title="Information Disclosure via X-Powered-By Header",
                    description=f"The HTTP response contains an X-Powered-By header revealing backend technologies: '{x_powered}'.",
                    severity=Severity.LOW,
                    endpoint=res.url,
                    remediation="Disable X-Powered-By header generation in web framework configuration.",
                    evidence=f"X-Powered-By: {x_powered}",
                    cvss_score=2.5,
                )
            )

        # Check X-AspNet-Version / X-Runtime
        for header_name in ("x-aspnet-version", "x-runtime", "x-backend-server"):
            if header_name in headers:
                findings.append(
                    Finding(
                        id=f"SERVER_INFO_DISCLOSURE_{header_name.upper().replace('-', '_')}",
                        title=f"Information Disclosure via {header_name} Header",
                        description=f"The header '{header_name}' exposes internal application runtime telemetry: '{headers[header_name]}'.",
                        severity=Severity.LOW,
                        endpoint=res.url,
                        remediation=f"Remove the '{header_name}' header from production response output.",
                        evidence=f"{header_name}: {headers[header_name]}",
                        cvss_score=2.0,
                    )
                )

        return findings
