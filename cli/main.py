#!/usr/bin/env python3
"""
Browser Cache Forensics Tool — Command Line Interface
Developed by Karanam Shrivasta
GitHub: https://github.com/mrshrivasta | LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

DISCLAIMER: Real-parses REAL Chrome/Chromium Simple Cache entry files on
this machine. Only run against browser profiles/paths you own or are
explicitly authorized to examine. Provided AS IS, no warranty.
See README.md for the full disclaimer.

Usage:
    python3 cli/main.py scan ~/.config/google-chrome/Default/Cache/Cache_Data --depth 4
    python3 cli/main.py scan ~/.config/google-chrome/Default/Cache/Cache_Data --json
    python3 cli/main.py scan /path/to/single/cache/entry_file --csv out.csv
    python3 cli/main.py rules
"""
import argparse
import csv
import io
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine
from app.detection_rules import ALL_RULES

BANNER = """\
==============================================================
 Browser Cache Forensics Tool (CLI)
 Developed by Karanam Shrivasta
 GitHub:   https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta
 DISCLAIMER: Authorized use only. Provided AS IS, no warranty.
==============================================================\
"""

SEVERITY_COLOR = {
    "critical": "\033[95m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"


def cmd_scan(args):
    print(BANNER)
    print(f"Scanning: {args.path}  (max depth {args.depth}, max files {args.max_files})\n")

    engine = ScanEngine(
        args.path,
        max_depth=args.depth,
        excludes=args.exclude.split(",") if args.exclude else None,
        max_files=args.max_files,
    )
    result = engine.run()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    print(f"Files scanned : {result['files_scanned']}")
    print(f"Dirs scanned  : {result['dirs_scanned']}")
    print(f"Errors        : {result['errors_count']}")
    print(f"Elapsed       : {result['elapsed_seconds']}s")
    print(f"Findings      : {len(result['findings'])}\n")

    for f in result["findings"]:
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"{color}[{f['severity'].upper():8}]{RESET} {f['rule_id']} {f['rule_name']}")
        print(f"           entry file: {f['file_path']}")
        print(f"           cache key : {f['permissions_octal']}")
        print(f"           {f['description']}\n")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["rule_id", "rule_name", "severity", "file_path", "cache_key", "description"])
            for f in result["findings"]:
                writer.writerow([f["rule_id"], f["rule_name"], f["severity"], f["file_path"], f["permissions_octal"], f["description"]])
        print(f"CSV report written to {args.csv}")

    if result["findings"]:
        sys.exit(1)  # non-zero exit for CI pipelines when issues are found
    sys.exit(0)


def cmd_rules(args):
    print(BANNER)
    print("Detection rules:\n")
    for rule in ALL_RULES:
        doc = (rule.__doc__ or "").strip().split("\n")[0]
        print(f" - {rule.__name__}: {doc}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="bcf-cli",
        description="Browser Cache Forensics Tool — real Chrome/Chromium Simple Cache binary parser (by Karanam Shrivasta).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Real-parse a Simple Cache directory or a single cache entry file")
    scan_p.add_argument("path", help="Cache_Data directory to walk, or a single cache entry file")
    scan_p.add_argument("--depth", type=int, default=6, help="Max recursion depth when scanning a directory (default 6)")
    scan_p.add_argument("--max-files", type=int, default=20000, dest="max_files", help="Safety cap on entry files parsed")
    scan_p.add_argument("--exclude", type=str, default="/proc,/sys,/dev,/run", help="Comma-separated paths to exclude while walking")
    scan_p.add_argument("--json", action="store_true", help="Output raw JSON")
    scan_p.add_argument("--csv", type=str, default=None, help="Write findings to a CSV file")
    scan_p.set_defaults(func=cmd_scan)

    rules_p = sub.add_parser("rules", help="List all detection rules")
    rules_p.set_defaults(func=cmd_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
