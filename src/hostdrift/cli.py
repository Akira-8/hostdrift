import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

from hostdrift.collectors.integrity import SensitiveFileCollector
from hostdrift.collectors.network import NetworkSocketCollector
from hostdrift.collectors.suid import PrivilegeSurfaceCollector
from hostdrift.diff import DriftEngine


def collect_telemetry(scan_dirs=None) -> Dict[str, Any]:
    suid_collector = PrivilegeSurfaceCollector(target_directories=scan_dirs)
    net_collector = NetworkSocketCollector()
    int_collector = SensitiveFileCollector()

    telemetry: Dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    telemetry.update(suid_collector.audit())
    telemetry.update(net_collector.audit())
    telemetry.update(int_collector.audit())
    return telemetry


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hostdrift",
        description="Linux Host Security Telemetry & Configuration Drift Auditor",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Run a one-off live telemetry audit")
    scan_parser.add_argument(
        "--dirs",
        nargs="+",
        default=["/bin", "/usr/bin", "/usr/local/bin", "/tmp"],
        help="Directories to scan for SUID/SGID/world-writable binaries",
    )

    # Subcommand: baseline
    base_parser = subparsers.add_parser("baseline", help="Capture and save a clean baseline state")
    base_parser.add_argument("-o", "--output", default="baseline.json", help="Output baseline JSON path")
    base_parser.add_argument(
        "--dirs",
        nargs="+",
        default=["/bin", "/usr/bin", "/usr/local/bin", "/tmp"],
        help="Directories to include in baseline",
    )

    # Subcommand: audit
    audit_parser = subparsers.add_parser("audit", help="Compare current host state against a saved baseline")
    audit_parser.add_argument("-b", "--baseline", default="baseline.json", help="Path to baseline JSON file")
    audit_parser.add_argument(
        "--dirs",
        nargs="+",
        default=["/bin", "/usr/bin", "/usr/local/bin", "/tmp"],
        help="Directories to scan",
    )

    args = parser.parse_args()

    if args.command == "scan":
        data = collect_telemetry(args.dirs)
        print(json.dumps(data, indent=2))

    elif args.command == "baseline":
        data = collect_telemetry(args.dirs)
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Baseline saved to {args.output}")

    elif args.command == "audit":
        if not os.path.exists(args.baseline):
            print(f"[!] Error: Baseline file '{args.baseline}' not found. Run 'baseline' first.", file=sys.stderr)
            sys.exit(2)

        with open(args.baseline, "r") as f:
            baseline_data = json.load(f)

        current_data = collect_telemetry(args.dirs)
        engine = DriftEngine()
        report = engine.compute_drift(baseline_data, current_data)
        print(json.dumps(report, indent=2))

        if report["drift_detected"]:
            sys.exit(1)


if __name__ == "__main__":
    main()