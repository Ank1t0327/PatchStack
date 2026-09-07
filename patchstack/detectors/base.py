from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from patchstack.scanner.http_client import HTTPClient, HTTPResponseTelemetry


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    endpoint: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
        }


class BaseDetector(ABC):
    """
    Abstract base class for all security detectors.
    """

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        """
        Executes security checks against target using HTTPClient and returns findings.
        """
        pass


class SecurityHeadersDetector(BaseDetector):
    """
    Foundation detector checking for critical missing security headers.
    """

    def __init__(self):
        super().__init__(
            name="security_headers",
            description="Analyzes HTTP response headers for missing security controls",
        )

    def scan(self, http_client: HTTPClient, target_url: str) -> List[Finding]:
        findings: List[Finding] = []
        res: Optional[HTTPResponseTelemetry] = http_client.get(target_url)

        if not res:
            return findings

        headers = {k.lower(): v for k, v in res.headers.items()}
        required_headers = {
            "content-security-policy": ("High", "Defines approved content sources to prevent XSS", 6.5),
            "x-frame-options": ("Medium", "Prevents clickjacking attacks by controlling framing", 4.3),
            "x-content-type-options": ("Low", "Prevents MIME-sniffing vulnerabilities", 3.1),
            "strict-transport-security": ("Medium", "Enforces HTTPS connections", 5.3),
        }

        for header_name, (sev, desc, cvss) in required_headers.items():
            if header_name not in headers:
                findings.append(
                    Finding(
                        id=f"MISSING_HEADER_{header_name.upper().replace('-', '_')}",
                        title=f"Missing Security Header: {header_name}",
                        description=f"The HTTP response does not include the standard security header '{header_name}'. {desc}.",
                        severity=Severity[sev.upper()],
                        endpoint=target_url,
                        remediation=f"Configure web server or application framework to set '{header_name}'.",
                        evidence={"endpoint": target_url, "missing_header": header_name},
                        cvss_score=cvss,
                    )
                )

        return findings
