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
            "endpoint": self.endpoint,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
        }

    def format_cli(self) -> str:
        return (
            f"Finding: {self.title}\n"
            f"Severity: {self.severity.value.capitalize()}\n"
            f"Endpoint: {self.endpoint}\n"
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
