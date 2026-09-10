import argparse
import json
import sys
from patchstack.config import ConfigManager
from patchstack.logger import StructuredLogger
from patchstack.scanner.engine import ScannerEngine
from patchstack.detectors.auth import AuthSessionDetector


def main():
    parser = argparse.ArgumentParser(description="PatchStack: Web Application Security Assessment CLI")
    parser.add_argument("-t", "--target", type=str, help="Target URL to assess (e.g., http://127.0.0.1:5000)")
    parser.add_argument("-c", "--config", type=str, help="Path to custom YAML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--json", action="store_true", help="Output scan results as raw JSON")
    parser.add_argument("--demo-auth", action="store_true", help="Execute Vulnerable -> Detect -> Explain -> Fix -> Retest Auth Demo")

    args = parser.parse_args()

    config = ConfigManager.load_config(args.config)
    if args.target:
        config.scanner.target_url = args.target
    if args.verbose:
        config.logging.level = "DEBUG"

    logger = StructuredLogger.get_logger(config=config.logging)

    if getattr(args, "demo_auth", False) or "--demo-auth" in sys.argv:
        target_base = config.scanner.target_url.rstrip("/")
        vulnerable_url = f"{target_base}/api/v1/auth/login-vulnerable"
        secure_url = f"{target_base}/api/v1/auth/login-secure"

        print("\n" + "=" * 70)
        print(" 🛡️  PATCHSTACK DAY 4: AUTHENTICATION & SESSION SECURITY DEMO")
        print("     Workflow: Vulnerable -> Detect -> Explain -> Fix -> Retest")
        print("=" * 70)

        detector = AuthSessionDetector()
        engine = ScannerEngine(config)

        print(f"\n PHASE 1: VULNERABILITY DETECTION (Target: {vulnerable_url})\n")
        vuln_findings = detector.scan(engine.http_client, vulnerable_url)

        print(f" [+] Found {len(vuln_findings)} Authentication & Session Security Flaw(s):\n")
        for i, f in enumerate(vuln_findings, 1):
            print(f" [{i}] Finding: {f.title}")
            print(f"     Severity:       {f.severity.value.capitalize()}")
            print(f"     Evidence:       {f.evidence}")
            print(f"     Recommendation: {f.remediation}")
            print("-" * 55)

        print("\n" + "=" * 70)
        print(" PHASE 2: SECURITY REMEDIATION & IMPLEMENTATION FIX")
        print("=" * 70)
        print("  Fix Applied in SecureAuthManager (/api/v1/auth/login-secure):")
        print("  1. Uniform Error Messages   : 'Invalid username or password' (No enumeration)")
        print("  2. High-Entropy Tokens       : secrets.token_urlsafe(32)")
        print("  3. Account Lockout/Limiting  : 15-min lockout after 5 failed attempts")
        print("  4. Secure Cookie Attributes  : HttpOnly; Secure; SameSite=Strict")

        print("\n" + "=" * 70)
        print(f" PHASE 3: RETESTING SECURE IMPLEMENTATION (Target: {secure_url})\n")
        secure_findings = detector.scan(engine.http_client, secure_url)

        print(f" [+] Retest Findings Count: {len(secure_findings)}")
        if len(secure_findings) == 0:
            print(" [✓] SUCCESS: All authentication & session security vulnerabilities REMEDIATED!")
        else:
            for f in secure_findings:
                print(f" [!] Remaining Finding: {f.title}")

        print("=" * 70 + "\n")
        return

    engine = ScannerEngine(config)
    result = engine.run(config.scanner.target_url)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("\n" + "=" * 60)
        print(" 🛡️  PATCHSTACK SECURITY ASSESSMENT REPORT")
        print("=" * 60)

        # Reconnaissance Summary Banner
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
