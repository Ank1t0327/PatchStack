"""
Security Detector Modules for PatchStack Platform.
"""

from patchstack.detectors.base import BaseDetector, Finding, Severity
from patchstack.detectors.headers import SecurityHeadersDetector
from patchstack.detectors.cookies import CookieSecurityDetector
from patchstack.detectors.info_disclosure import ServerInfoDisclosureDetector
from patchstack.detectors.methods import DangerousMethodsDetector
from patchstack.detectors.cors import CORSConfigDetector
from patchstack.detectors.auth import AuthSessionDetector
from patchstack.detectors.sqli import SQLInjectionDetector
from patchstack.detectors.xss import XSSDetector
from patchstack.detectors.idor import IDORAccessControlDetector

__all__ = [
    "BaseDetector",
    "Finding",
    "Severity",
    "SecurityHeadersDetector",
    "CookieSecurityDetector",
    "ServerInfoDisclosureDetector",
    "DangerousMethodsDetector",
    "CORSConfigDetector",
    "AuthSessionDetector",
    "SQLInjectionDetector",
    "XSSDetector",
    "IDORAccessControlDetector",
]
