import time
from typing import Optional
from patchstack.config import ScannerConfig
from patchstack.logger import StructuredLogger
from patchstack.scanner.http_client import HTTPClient
from patchstack.recon.models import ReconResult, TargetFingerprint
from patchstack.recon.crawler import WebCrawler
from patchstack.recon.fingerprint import TechnologyFingerprinter
from patchstack.recon.parser import HTMLReconParser


class ReconEngine:
    """
    HTTP Reconnaissance Engine orchestrating web crawling, endpoint discovery, HTML form parsing,
    cookie extraction, and server technology fingerprinting.
    """

    def __init__(self, config: Optional[ScannerConfig] = None, http_client: Optional[HTTPClient] = None):
        self.config = config or ScannerConfig()
        self.http_client = http_client or HTTPClient(self.config)
        self.logger = StructuredLogger.get_logger()

    def run(self, target_url: str, max_depth: int = 2) -> ReconResult:
        self.logger.info(f"Initiating HTTP Reconnaissance against target: {target_url}")
        start_time = time.perf_counter()

        crawler = WebCrawler(self.http_client, max_depth=max_depth)
        endpoints, forms, cookies, telemetry_history = crawler.crawl(target_url)

        # Fingerprint initial response or first successful telemetry
        fingerprint = TargetFingerprint()
        if telemetry_history:
            initial_telemetry = telemetry_history[0]
            _, _, _, meta_tags = HTMLReconParser.parse_html(initial_telemetry.body, initial_telemetry.url)
            fingerprint = TechnologyFingerprinter.analyze(initial_telemetry, meta_tags)

        recon_duration_ms = (time.perf_counter() - start_time) * 1000.0

        result = ReconResult(
            target_url=target_url,
            endpoints=endpoints,
            forms=forms,
            cookies=cookies,
            fingerprint=fingerprint,
            recon_duration_ms=recon_duration_ms,
        )

        self.logger.info(
            f"Recon completed in {result.recon_duration_ms:.2f}ms. Discovered: "
            f"{result.total_endpoints} endpoint(s), {result.total_forms} form(s), {result.total_cookies} cookie(s). "
            f"Server: {fingerprint.server} ({fingerprint.framework})"
        )

        return result
