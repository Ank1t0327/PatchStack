from typing import List, Dict, Tuple, Set
from patchstack.detectors.base import Finding, Severity


class RiskEngine:
    """
    Risk Engine performing:
    - Finding deduplication
    - CWE & OWASP Top 10 mapping enrichment
    - Severity distribution metrics calculation
    - Normalized overall target risk score computation (0.0 to 10.0 scale)
    """

    # Static CWE & OWASP Mapping Registry
    MAPPING_TABLE = {
        "SQLI_ERROR_BASED": ("CWE-89", "A03:2021-Injection"),
        "SQLI_BOOLEAN_BASED": ("CWE-89", "A03:2021-Injection"),
        "XSS_REFLECTED": ("CWE-79", "A03:2021-Injection"),
        "IDOR_HORIZONTAL_PRIVILEGE_ESCALATION": ("CWE-639", "A01:2021-Broken Access Control"),
        "AUTH_USERNAME_ENUMERATION": ("CWE-203", "A07:2021-Identification & Auth Failures"),
        "AUTH_PREDICTABLE_SESSION_ID": ("CWE-330", "A07:2021-Identification & Auth Failures"),
        "AUTH_MISSING_RATE_LIMITING": ("CWE-307", "A07:2021-Identification & Auth Failures"),
        "AUTH_INSECURE_SESSION_COOKIE": ("CWE-614", "A05:2021-Security Misconfiguration"),
        "CORS_ARBITRARY_ORIGIN_REFLECTED_WITH_CREDENTIALS": ("CWE-942", "A05:2021-Security Misconfiguration"),
        "CORS_ARBITRARY_ORIGIN_REFLECTED": ("CWE-942", "A05:2021-Security Misconfiguration"),
        "CORS_WILDCARD_WITH_CREDENTIALS": ("CWE-942", "A05:2021-Security Misconfiguration"),
        "CORS_NULL_ORIGIN_ALLOWED": ("CWE-942", "A05:2021-Security Misconfiguration"),
        "DANGEROUS_METHOD_TRACE_ENABLED": ("CWE-16", "A05:2021-Security Misconfiguration"),
        "DANGEROUS_METHOD_PUT_ENABLED": ("CWE-16", "A05:2021-Security Misconfiguration"),
        "DANGEROUS_METHOD_DELETE_ENABLED": ("CWE-16", "A05:2021-Security Misconfiguration"),
        "SERVER_INFO_DISCLOSURE_SERVER_HEADER": ("CWE-200", "A05:2021-Security Misconfiguration"),
        "SERVER_INFO_DISCLOSURE_X_POWERED_BY": ("CWE-200", "A05:2021-Security Misconfiguration"),
        "COOKIE_MISSING_HTTPONLY": ("CWE-1004", "A05:2021-Security Misconfiguration"),
        "COOKIE_MISSING_SECURE": ("CWE-614", "A05:2021-Security Misconfiguration"),
        "COOKIE_WEAK_SAMESITE": ("CWE-1275", "A01:2021-Broken Access Control"),
        "MISSING_CONTENT_SECURITY_POLICY": ("CWE-1021", "A05:2021-Security Misconfiguration"),
        "MISSING_X_FRAME_OPTIONS": ("CWE-1021", "A05:2021-Security Misconfiguration"),
        "MISSING_X_CONTENT_TYPE_OPTIONS": ("CWE-693", "A05:2021-Security Misconfiguration"),
        "MISSING_STRICT_TRANSPORT_SECURITY": ("CWE-523", "A05:2021-Security Misconfiguration"),
    }

    @classmethod
    def enrich_and_deduplicate(cls, findings: List[Finding]) -> List[Finding]:
        """
        Enriches findings with CWE and OWASP mappings, then deduplicates based on (id, endpoint, parameter).
        """
        deduped: List[Finding] = []
        seen_keys: Set[Tuple[str, str, str]] = set()

        for finding in findings:
            # Map CWE and OWASP if present in table
            if finding.id in cls.MAPPING_TABLE:
                cwe_code, owasp_cat = cls.MAPPING_TABLE[finding.id]
                finding.cwe = cwe_code
                finding.owasp_category = owasp_cat

            # Assign parameter if present in evidence
            if not finding.parameter:
                if "Parameter: " in finding.evidence:
                    try:
                        param_val = finding.evidence.split("Parameter: ")[1].split(" ")[0].split("|")[0].strip()
                        finding.parameter = param_val
                    except Exception:
                        pass

            dedup_key = (finding.id, finding.endpoint, finding.parameter or "")
            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                deduped.append(finding)

        return deduped

    @classmethod
    def calculate_severity_counts(cls, findings: List[Finding]) -> Dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev_key = f.severity.value.capitalize()
            if sev_key in counts:
                counts[sev_key] += 1
        return counts

    @classmethod
    def calculate_risk_score(cls, findings: List[Finding]) -> float:
        """
        Calculates normalized risk score (0.0 to 10.0 scale) based on finding severities and confidence levels.
        """
        if not findings:
            return 0.0

        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.5,
        }
        confidence_multipliers = {
            "High": 1.0,
            "Medium": 0.8,
            "Low": 0.5,
        }

        total_weight = 0.0
        for f in findings:
            w = weights.get(f.severity, 1.0)
            c = confidence_multipliers.get(f.confidence, 1.0)
            total_weight += w * c

        # Normalize score on 0.0 to 10.0 scale with logarithmic saturation
        normalized_score = min(10.0, total_weight / 1.5)
        return round(normalized_score, 1)
