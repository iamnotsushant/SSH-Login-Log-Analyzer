#!/usr/bin/env python3
"""Summarize SSH authentication log lines and flag repeated failures."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
INVALID = re.compile(r"Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")


def valid_ipv4(address: str) -> bool:
    parts = address.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def analyze(lines, threshold=3):
    """Return aggregate findings from SSH auth log lines; no log content is modified."""
    failures_by_ip = Counter()
    failures_by_user = Counter()
    successes_by_ip = Counter()
    invalid_users = Counter()
    total_failed = total_success = 0
    for line in lines:
        match = FAILED.search(line)
        if match and valid_ipv4(match.group(2)):
            user, ip = match.groups()
            failures_by_ip[ip] += 1
            failures_by_user[user] += 1
            total_failed += 1
            continue
        match = ACCEPTED.search(line)
        if match and valid_ipv4(match.group(2)):
            _, ip = match.groups()
            successes_by_ip[ip] += 1
            total_success += 1
            continue
        match = INVALID.search(line)
        if match and valid_ipv4(match.group(2)):
            invalid_users[match.group(1)] += 1
    flagged = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in failures_by_ip.most_common()
        if count >= threshold
    ]
    return {
        "summary": {
            "failed_logins": total_failed,
            "successful_logins": total_success,
            "unique_source_ips_with_failures": len(failures_by_ip),
            "unique_source_ips_with_successes": len(successes_by_ip),
            "threshold": threshold,
        },
        "repeated_failures": flagged,
        "top_failed_usernames": [
            {"username": name, "attempts": count}
            for name, count in failures_by_user.most_common(5)
        ],
        "invalid_usernames": [
            {"username": name, "attempts": count}
            for name, count in invalid_users.most_common(5)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="authorized SSH authentication log file")
    parser.add_argument("--threshold", type=int, default=3, help="failures from one IP to flag (default: 3)")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    try:
        with args.logfile.open(encoding="utf-8", errors="replace") as file:
            report = analyze(file, args.threshold)
    except OSError as error:
        parser.error(str(error))
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print(f"SSH log summary: {args.logfile}")
    for key, value in report["summary"].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    print("\nRepeated failures:")
    if report["repeated_failures"]:
        for item in report["repeated_failures"]:
            print(f"  {item['ip']}: {item['failed_attempts']} failed attempts")
    else:
        print("  None met the threshold")
    print("\nTop failed usernames:")
    for item in report["top_failed_usernames"]:
        print(f"  {item['username']}: {item['attempts']}")


if __name__ == "__main__":
    main()
