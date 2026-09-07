import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import yaml


@dataclass
class ScannerConfig:
    target_url: str = "http://127.0.0.1:5000"
    timeout: int = 10
    user_agent: str = "PatchStack-Security-Scanner/1.0"
    follow_redirects: bool = True
    max_retries: int = 3
    threads: int = 4


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "console"
    file_path: str = "patchstack_scan.log"
    verbose: bool = False


@dataclass
class Config:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    enabled_detectors: List[str] = field(default_factory=lambda: ["security_headers", "info_disclosure", "cors_misconfig"])
    output_dir: str = "reports/output"
    default_format: str = "json"


class ConfigManager:
    """
    Manages loading, parsing, and environment variable overrides for PatchStack config.
    """

    @staticmethod
    def load_config(config_path: Optional[str] = None) -> Config:
        raw_data: Dict[str, Any] = {}

        # Default path check
        default_path = os.path.join(os.path.dirname(__file__), "..", "config", "default_config.yaml")
        path_to_load = config_path or default_path

        if os.path.exists(path_to_load):
            with open(path_to_load, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f) or {}

        scanner_data = raw_data.get("scanner", {})
        logging_data = raw_data.get("logging", {})
        detectors_data = raw_data.get("detectors", {})
        reports_data = raw_data.get("reports", {})

        scanner_cfg = ScannerConfig(
            target_url=os.getenv("PATCHSTACK_TARGET", scanner_data.get("target_url", "http://127.0.0.1:5000")),
            timeout=int(os.getenv("PATCHSTACK_TIMEOUT", scanner_data.get("timeout", 10))),
            user_agent=os.getenv("PATCHSTACK_USER_AGENT", scanner_data.get("user_agent", "PatchStack-Security-Scanner/1.0")),
            follow_redirects=bool(scanner_data.get("follow_redirects", True)),
            max_retries=int(scanner_data.get("max_retries", 3)),
            threads=int(scanner_data.get("threads", 4)),
        )

        logging_cfg = LoggingConfig(
            level=os.getenv("PATCHSTACK_LOG_LEVEL", logging_data.get("level", "INFO")),
            format=logging_data.get("format", "console"),
            file_path=logging_data.get("file_path", "patchstack_scan.log"),
            verbose=bool(logging_data.get("verbose", False)),
        )

        enabled_detectors = detectors_data.get("enabled", ["security_headers", "info_disclosure", "cors_misconfig"])
        output_dir = reports_data.get("output_dir", "reports/output")
        default_format = reports_data.get("default_format", "json")

        return Config(
            scanner=scanner_cfg,
            logging=logging_cfg,
            enabled_detectors=enabled_detectors,
            output_dir=output_dir,
            default_format=default_format,
        )
