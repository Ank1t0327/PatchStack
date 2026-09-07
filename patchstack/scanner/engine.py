from dataclasses import dataclass, field
from typing import List, Dict, Any
from patchstack.config import Config
from patchstack.logger import StructuredLogger
from patchstack.scanner.http_client import HTTPClient
from patchstack.detectors.base import BaseDetector, Finding, SecurityHeadersDetector


@dataclass
class ScanResult:
    target_url: str
    total_findings: int
    findings: List[Finding]
    risk_score: float
    scan_duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "total_findings": self.total_findings,
            "risk_score": round(self.risk_score, 2),
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "findings": [f.to_dict() for f in self.findings],
        }


class ScannerEngine:
    """
    Core security assessment engine orchestrating HTTP client, detectors, and scan result compilation.
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = StructuredLogger.get_logger(config=config.logging)
        self.http_client = HTTPClient(config.scanner)
        self.detectors: List[BaseDetector] = []

        # Register default detectors
        self._register_default_detectors()

    def _register_default_detectors(self):
        # Register foundation detectors matching config
        if "security_headers" in self.config.enabled_detectors:
            self.register_detector(SecurityHeadersDetector())

    def register_detector(self, detector: BaseDetector):
        self.detectors.append(detector)
        self.logger.debug(f"Registered detector: {detector.name}")

    def run(self, target_url: Optional[str] = None) -> ScanResult:
        url = target_url or self.config.scanner.target_url
        self.logger.info(f"Starting PatchStack Security Scan against target: {url}")

        if not self.http_client.verify_target_reachable(url):
            self.logger.warning(f"Target URL {url} is not reachable or returned server error.")

        all_findings: List[Finding] = []
        import time
        start_time = time.perf_counter()

        for detector in self.detectors:
            self.logger.info(f"Running detector module: {detector.name}")
            try:
                findings = detector.scan(self.http_client, url)
                all_findings.extend(findings)
                self.logger.info(f"Detector {detector.name} produced {len(findings)} finding(s)")
            except Exception as e:
                self.logger.error(f"Error running detector {detector.name}: {e}")

        scan_duration_ms = (time.perf_counter() - start_time) * 1000.0
        risk_score = sum(f.cvss_score for f in all_findings)

        result = ScanResult(
            target_url=url,
            total_findings=len(all_findings),
            findings=all_findings,
            risk_score=risk_score,
            scan_duration_ms=scan_duration_ms,
        )

        self.logger.info(f"Scan complete. Total findings: {result.total_findings}, Risk score: {result.risk_score:.1f}")
        return result
