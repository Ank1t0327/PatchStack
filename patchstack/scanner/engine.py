from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from patchstack.config import Config
from patchstack.logger import StructuredLogger
from patchstack.scanner.http_client import HTTPClient
from patchstack.detectors.base import BaseDetector, Finding
from patchstack.detectors.headers import SecurityHeadersDetector
from patchstack.detectors.cookies import CookieSecurityDetector
from patchstack.detectors.info_disclosure import ServerInfoDisclosureDetector
from patchstack.detectors.methods import DangerousMethodsDetector
from patchstack.detectors.cors import CORSConfigDetector
from patchstack.detectors.auth import AuthSessionDetector
from patchstack.detectors.sqli import SQLInjectionDetector
from patchstack.detectors.xss import XSSDetector
from patchstack.detectors.idor import IDORAccessControlDetector
from patchstack.recon.engine import ReconEngine
from patchstack.recon.models import ReconResult
from patchstack.risk.engine import RiskEngine
from patchstack.reports.html_report import HTMLReportExporter
from patchstack.storage.db import ScanDatabaseManager


@dataclass
class ScanResult:
    target_url: str
    total_findings: int
    findings: List[Finding]
    risk_score: float
    scan_duration_ms: float
    recon: Optional[ReconResult] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "target_url": self.target_url,
            "total_findings": self.total_findings,
            "risk_score": round(self.risk_score, 1),
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.recon:
            data["recon"] = self.recon.to_dict()
        return data


class ScannerEngine:
    """
    Core security assessment engine orchestrating:
    Recon -> Discovery -> Detectors -> Risk Engine -> Database -> HTML Report Exporter
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = StructuredLogger.get_logger(config=config.logging)
        self.http_client = HTTPClient(config.scanner)
        self.recon_engine = ReconEngine(config.scanner, self.http_client)
        self.db_manager = ScanDatabaseManager()
        self.detectors: List[BaseDetector] = []

        # Register default detectors
        self._register_default_detectors()

    def _register_default_detectors(self):
        detector_map = {
            "security_headers": SecurityHeadersDetector,
            "cookie_security": CookieSecurityDetector,
            "info_disclosure": ServerInfoDisclosureDetector,
            "dangerous_methods": DangerousMethodsDetector,
            "cors_misconfig": CORSConfigDetector,
            "auth_session": AuthSessionDetector,
            "sqli_detector": SQLInjectionDetector,
            "xss_detector": XSSDetector,
            "idor_detector": IDORAccessControlDetector,
        }

        for name in self.config.enabled_detectors:
            if name in detector_map:
                self.register_detector(detector_map[name]())

    def register_detector(self, detector: BaseDetector):
        self.detectors.append(detector)
        self.logger.debug(f"Registered detector: {detector.name}")

    def run(self, target_url: Optional[str] = None) -> ScanResult:
        url = target_url or self.config.scanner.target_url
        self.logger.info(f"Starting PatchStack Security Scan against target: {url}")

        if not self.http_client.verify_target_reachable(url):
            self.logger.warning(f"Target URL {url} is not reachable or returned server error.")

        # Phase 1: Reconnaissance & Discovery
        self.logger.info("Phase 1: Executing HTTP Target Reconnaissance & Discovery...")
        recon_result = self.recon_engine.run(url)

        # Phase 2: Vulnerability Detectors Execution
        self.logger.info("Phase 2: Running Security Vulnerability Detectors...")
        raw_findings: List[Finding] = []
        import time
        start_time = time.perf_counter()

        for detector in self.detectors:
            self.logger.info(f"Running detector module: {detector.name}")
            try:
                findings = detector.scan(self.http_client, url)
                raw_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"Error running detector {detector.name}: {e}")

        # Phase 3: Risk Engine Processing (Deduplication, Mappings & 0-10 Risk Score Calculation)
        self.logger.info("Phase 3: Processing Risk Engine (Deduplication, CWE/OWASP Mappings, Risk Scoring)...")
        deduped_findings = RiskEngine.enrich_and_deduplicate(raw_findings)
        risk_score = RiskEngine.calculate_risk_score(deduped_findings)
        scan_duration_ms = (time.perf_counter() - start_time) * 1000.0

        result = ScanResult(
            target_url=url,
            total_findings=len(deduped_findings),
            findings=deduped_findings,
            risk_score=risk_score,
            scan_duration_ms=scan_duration_ms,
            recon=recon_result,
        )

        # Phase 4: Database Storage
        self.logger.info("Phase 4: Persisting Scan Results to SQLite Database (patchstack.db)...")
        try:
            self.db_manager.save_scan_result(result)
        except Exception as e:
            self.logger.error(f"Error saving scan result to database: {e}")

        # Phase 5: Export Standalone HTML Security Report
        self.logger.info("Phase 5: Generating Executive HTML Security Assessment Report...")
        try:
            html_exporter = HTMLReportExporter()
            html_exporter.export(result, "reports/output/patchstack_report.html")
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")

        self.logger.info(
            f"Full Audit Complete. Endpoints: {recon_result.total_endpoints}, "
            f"Findings: {result.total_findings}, Risk Score: {result.risk_score}/10"
        )
        return result
