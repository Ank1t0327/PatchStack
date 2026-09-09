from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    default_value: str = ""
    required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.field_type,
            "default_value": self.default_value,
            "required": self.required,
        }


@dataclass
class DiscoveredForm:
    action: str
    method: str
    fields: List[FormField] = field(default_factory=list)
    source_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method.upper(),
            "source_url": self.source_url,
            "fields": [f.to_dict() for f in self.fields],
        }


@dataclass
class DiscoveredEndpoint:
    url: str
    path: str
    method: str = "GET"
    status_code: int = 200
    content_type: str = "text/html"
    depth: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "depth": self.depth,
        }


@dataclass
class TargetFingerprint:
    server: str = "Unknown"
    framework: str = "Unknown"
    programming_language: str = "Unknown"
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "framework": self.framework,
            "programming_language": self.programming_language,
            "technologies": self.technologies,
            "headers": self.headers,
            "cookies": self.cookies,
        }


@dataclass
class ReconResult:
    target_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    fingerprint: TargetFingerprint = field(default_factory=TargetFingerprint)
    recon_duration_ms: float = 0.0

    @property
    def total_endpoints(self) -> int:
        return len(self.endpoints)

    @property
    def total_forms(self) -> int:
        return len(self.forms)

    @property
    def total_cookies(self) -> int:
        return len(self.cookies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "total_endpoints": self.total_endpoints,
            "total_forms": self.total_forms,
            "total_cookies": self.total_cookies,
            "fingerprint": self.fingerprint.to_dict(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "cookies": self.cookies,
            "recon_duration_ms": round(self.recon_duration_ms, 2),
        }
