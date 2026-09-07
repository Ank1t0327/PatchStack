import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import requests
from patchstack.config import ScannerConfig
from patchstack.logger import StructuredLogger


@dataclass
class HTTPResponseTelemetry:
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    cookies: Dict[str, str] = field(default_factory=dict)


class HTTPClient:
    """
    HTTP Client wrapper with request/response telemetry and session handling.
    """

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = StructuredLogger.get_logger()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.config.user_agent})

    def request(self, method: str, url: str, **kwargs) -> Optional[HTTPResponseTelemetry]:
        timeout = kwargs.pop("timeout", self.config.timeout)
        allow_redirects = kwargs.pop("allow_redirects", self.config.follow_redirects)

        start_time = time.perf_counter()
        try:
            res = self.session.request(
                method=method.upper(),
                url=url,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            telemetry = HTTPResponseTelemetry(
                url=res.url,
                status_code=res.status_code,
                headers=dict(res.headers),
                body=res.text,
                elapsed_ms=round(elapsed_ms, 2),
                cookies=requests.utils.dict_from_cookiejar(res.cookies),
            )
            self.logger.debug(f"HTTP {method.upper()} {url} -> {res.status_code} ({telemetry.elapsed_ms}ms)")
            return telemetry
        except requests.RequestException as e:
            self.logger.error(f"HTTP Request failed [{method.upper()} {url}]: {e}")
            return None

    def get(self, url: str, **kwargs) -> Optional[HTTPResponseTelemetry]:
        return self.request("GET", url, **kwargs)

    def verify_target_reachable(self, target_url: str) -> bool:
        """Checks whether the target server responds."""
        res = self.get(target_url)
        return res is not None and res.status_code < 500
