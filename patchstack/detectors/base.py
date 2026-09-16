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
    evidence: str = "Header or property not present"
    confidence: str = "High"  # High, Medium, Low
    parameter: Optional[str] = None
    cwe: str = "CWE-200"
    owasp_category: str = "A05:2021-Security Misconfiguration"
    cvss_score: float = 0.0

    @property
    def recommendation(self) -> str:
        return self.remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "endpoint": self.endpoint,
            "parameter": self.parameter or "N/A",
            "cwe": self.cwe,
            "owasp_category": self.owasp_category,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
        }

    def format_cli(self) -> str:
        param_str = f"\nParameter: {self.parameter}" if self.parameter else ""
        return (
            f"Finding: {self.title}\n"
            f"Severity: {self.severity.value.capitalize()}\n"
            f"Confidence: {self.confidence}\n"
            f"Endpoint: {self.endpoint}{param_str}\n"
            f"CWE: {self.cwe} | OWASP: {self.owasp_category}\n"
            f"Evidence: {self.evidence}\n"
            f"Recommendation: {self.recommendation}"
        )


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
