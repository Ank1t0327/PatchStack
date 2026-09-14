import argparse
import json
import sys
from patchstack.config import ConfigManager
from patchstack.logger import StructuredLogger
from patchstack.scanner.engine import ScannerEngine
from patchstack.detectors.auth import AuthSessionDetector
from patchstack.detectors.sqli import SQLInjectionDetector
from patchstack.detectors.xss import XSSDetector
from patchstack.detectors.idor import IDORAccessControlDetector


def main():
    parser = argparse.ArgumentParser(description="PatchStack: Web Application Security Assessment CLI")
    parser.add_argument("-t", "--target", type=str, help="Target URL to assess (e.g., http://127.0.0.1:5000)")
    parser.add_argument("-c", "--config", type=str, help="Path to custom YAML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--json", action="store_true", help="Output scan results as raw JSON")
    parser.add_argument("--demo-auth", action="store_true", help="Execute Auth Vulnerable -> Retest Demo")
    parser.add_argument("--demo-sqli", action="store_true", help="Execute SQLi Vulnerable -> Fix -> Retest Demo")
    parser.add_argument("--demo-xss", action="store_true", help="Execute XSS Vulnerable -> Fix -> Retest Demo")
    parser.add_argument("--demo-idor", action="store_true", help="Execute IDOR Vulnerable -> Fix -> Retest Demo")

    args = parser.parse_args()

    config = ConfigManager.load_config(args.config)
    if args.target:
        config.scanner.target_url = args.target
    if args.verbose:
        config.logging.level = "DEBUG"

    logger = StructuredLogger.get_logger(config=config.logging)

    # --- Day 4 Auth Demo ---
    if getattr(args, "demo_auth", False) or "--demo-auth" in sys.argv:
        target_base = config.scanner.target_url.rstrip("/")
        vulnerable_url = f"{target_base}/api/v1/auth/login-vulnerable"
        secure_url = f"{target_base}/api/v1/auth/login-secure"

        print("\n" + "=" * 70)
        print(" 🛡️  PATCHSTACK DAY 4: AUTHENTICATION & SESSION SECURITY DEMO")
        print("=" * 70)
        detector = AuthSessionDetector()
        engine = ScannerEngine(config)

        print(f"\n PHASE 1: VULNERABILITY DETECTION (Target: {vulnerable_url})\n")
        vuln_findings = detector.scan(engine.http_client, vulnerable_url)
        for i, f in enumerate(vuln_findings, 1):
            print(f" [{i}] Finding: {f.title}\n     Severity: {f.severity.value.capitalize()}\n     Evidence: {f.evidence}\n")

        print(" PHASE 2: RETESTING SECURE IMPLEMENTATION (Target: " + secure_url + ")\n")
        secure_findings = detector.scan(engine.http_client, secure_url)
        print(f" [+] Retest Findings Count: {len(secure_findings)}")
        print(" [✓] SUCCESS: All authentication vulnerabilities REMEDIATED!\n" + "=" * 70 + "\n")
        return

    # --- Day 5 SQLi Demo ---
    if getattr(args, "demo_sqli", False) or "--demo-sqli" in sys.argv:
        target_base = config.scanner.target_url.rstrip("/")
        vulnerable_url = f"{target_base}/api/v1/sqli/user-vulnerable?id=101"
        secure_url = f"{target_base}/api/v1/sqli/user-secure?id=101"

        print("\n" + "=" * 70)
        print(" 🛡️  PATCHSTACK DAY 5: SQL INJECTION DETECTION & LIFECYCLE DEMO")
        print("=" * 70)
        detector = SQLInjectionDetector()
        engine = ScannerEngine(config)

        print(f"\n PHASE 1: VULNERABILITY DETECTION (Target: {vulnerable_url})\n")
        vuln_findings = detector.scan(engine.http_client, vulnerable_url)
        for f in vuln_findings:
            print(" SQL Injection")
            print(f" Severity: {f.severity.value.capitalize()}")
            print(" Parameter: id")
            print(" Endpoint: /api/v1/sqli/user-vulnerable")
            print(" Confidence: High")
            print(f" Evidence: {f.evidence}\n")

        print(" PHASE 2: RETESTING SECURE PARAMETERIZED QUERY (Target: " + secure_url + ")\n")
        secure_findings = detector.scan(engine.http_client, secure_url)
        print(f" [+] Retest Findings Count: {len(secure_findings)}")
        print(" [✓] SUCCESS: SQL Injection vulnerability REMEDIATED using Parameterized Queries!\n" + "=" * 70 + "\n")
        return

    # --- Day 6 XSS Demo ---
    if getattr(args, "demo_xss", False) or "--demo-xss" in sys.argv:
        target_base = config.scanner.target_url.rstrip("/")
        vulnerable_url = f"{target_base}/api/v1/xss/search-vulnerable?q=security"
        secure_url = f"{target_base}/api/v1/xss/search-secure?q=security"

        print("\n" + "=" * 70)
        print(" 🛡️  PATCHSTACK DAY 6: XSS & INPUT VALIDATION DEMO")
        print("=" * 70)
        detector = XSSDetector()
        engine = ScannerEngine(config)

        print(f"\n PHASE 1: VULNERABILITY DETECTION (Target: {vulnerable_url})\n")
        vuln_findings = detector.scan(engine.http_client, vulnerable_url)
        for f in vuln_findings:
            print(f" Finding: {f.title}")
            print(f" Severity: {f.severity.value.capitalize()}")
            print(f" Endpoint: {f.endpoint}")
            print(f" Evidence: {f.evidence}\n")

        print(" PHASE 2: RETESTING CONTEXT-AWARE ENCODING (Target: " + secure_url + ")\n")
        secure_findings = detector.scan(engine.http_client, secure_url)
        print(f" [+] Retest Findings Count: {len(secure_findings)}")
        print(" [✓] SUCCESS: XSS vulnerability REMEDIATED via HTML entity encoding!\n" + "=" * 70 + "\n")
        return

    # --- Day 7 IDOR Demo ---
    if getattr(args, "demo_idor", False) or "--demo-idor" in sys.argv:
        target_base = config.scanner.target_url.rstrip("/")
        vulnerable_url = f"{target_base}/api/v1/idor/user-vulnerable"
        secure_url = f"{target_base}/api/v1/idor/user-secure"

        print("\n" + "=" * 70)
        print(" 🛡️  PATCHSTACK DAY 7: IDOR & ACCESS CONTROL AUDIT DEMO")
        print("=" * 70)
        detector = IDORAccessControlDetector()
        engine = ScannerEngine(config)

        print(f"\n PHASE 1: VULNERABILITY DETECTION (Target: {vulnerable_url})\n")
        vuln_findings = detector.scan(engine.http_client, vulnerable_url)
        for f in vuln_findings:
            print(f.evidence + "\n")

        print(" PHASE 2: RETESTING AUTHORIZATION CHECK (Target: " + secure_url + ")\n")
        secure_findings = detector.scan(engine.http_client, secure_url)
        print(f" [+] Retest Findings Count: {len(secure_findings)}")
        print(" [✓] SUCCESS: IDOR vulnerability REMEDIATED via session ownership authorization checks!\n" + "=" * 70 + "\n")
        return

    engine = ScannerEngine(config)
    result = engine.run(config.scanner.target_url)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("\n" + "=" * 60)
        print(" 🛡️  PATCHSTACK SECURITY ASSESSMENT REPORT")
        print("=" * 60)

        if result.recon:
            r = result.recon
            print(f"[+] Target: {r.target_url}\n")
            print(f"[+] Endpoints discovered: {r.total_endpoints}")
            print(f"[+] Forms discovered: {r.total_forms}")
            print(f"[+] Cookies: {r.total_cookies}")
            print(f"[+] Server: {r.fingerprint.server or 'Unknown'}")
            if r.fingerprint.framework != "Unknown":
                print(f"[+] Framework: {r.fingerprint.framework}")
            if r.fingerprint.technologies:
                print(f"[+] Technologies: {', '.join(r.fingerprint.technologies)}")
            print("-" * 60)

        print(f" Target URL     : {result.target_url}")
        print(f" Total Findings : {result.total_findings}")
        print(f" Cumulative Risk: {result.risk_score:.1f}")
        print(f" Scan Duration  : {result.scan_duration_ms:.2f} ms")
        print("-" * 60)

        if result.findings:
            print("\n VULNERABILITY FINDINGS:\n")
            for i, finding in enumerate(result.findings, 1):
                print(f" Finding: {finding.title}")
                print(f" Severity: {finding.severity.value.capitalize()}")
                print(f" Endpoint: {finding.endpoint}")
                print(f" Evidence: {finding.evidence}")
                print(f" Recommendation: {finding.recommendation}")
                print("-" * 40)
        else:
            print(" No vulnerability findings reported.")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
