import argparse
import json
import sys
from patchstack.config import ConfigManager
from patchstack.logger import StructuredLogger
from patchstack.scanner.engine import ScannerEngine


def main():
    parser = argparse.ArgumentParser(description="PatchStack: Web Application Security Assessment CLI")
    parser.add_argument("-t", "--target", type=str, help="Target URL to assess (e.g., http://127.0.0.1:5000)")
    parser.add_argument("-c", "--config", type=str, help="Path to custom YAML configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--json", action="store_true", help="Output scan results as raw JSON")

    args = parser.parse_args()

    config = ConfigManager.load_config(args.config)
    if args.target:
        config.scanner.target_url = args.target
    if args.verbose:
        config.logging.level = "DEBUG"

    logger = StructuredLogger.get_logger(config=config.logging)

    engine = ScannerEngine(config)
    result = engine.run(config.scanner.target_url)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("\n" + "=" * 60)
        print(f" 🛡️  PATCHSTACK SECURITY ASSESSMENT REPORT")
        print("=" * 60)
        print(f" Target URL     : {result.target_url}")
        print(f" Total Findings : {result.total_findings}")
        print(f" Cumulative Risk: {result.risk_score:.1f}")
        print(f" Duration       : {result.scan_duration_ms:.2f} ms")
        print("-" * 60)
        for i, finding in enumerate(result.findings, 1):
            print(f" [{i}] [{finding.severity.value}] {finding.title}")
            print(f"     ID:          {finding.id}")
            print(f"     Remediation: {finding.remediation}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
