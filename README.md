# SSH Login Log Analyzer

A standard-library Python command-line tool that counts SSH authentication successes and failures and highlights source IPs that meet a configurable failed-login threshold. Its sample data report uses concise, editorial formatting to match the rest of the portfolio projects.

## Run

From this folder:

```bash
python3 log_analyzer.py sample_auth.log
python3 log_analyzer.py sample_auth.log --threshold 2 --json
python3 -m unittest -v
```

No third-party packages are required. The included log uses documentation-only IP ranges and is synthetic.

## What it demonstrates

- Python regular expressions, counters, functions, CLI arguments, JSON output, and unit tests
- Parsing semi-structured event records and aggregating indicators
- A simple detection threshold with an explicit and adjustable rule

## Limitations and safe use

This is a small demonstration, not a production intrusion detection system. It supports a narrow subset of common OpenSSH log formats, uses IPv4 patterns, and does not correlate events over time or distinguish users behind shared addresses. A repeated failure is a signal to investigate, not proof of an attack. Analyze only logs you are authorized to access; review privacy and retention requirements before handling real logs.

## Portfolio description

> Developed a Python CLI that parses sample SSH authentication events, summarizes login activity, flags repeated failures by source IP, and exports JSON. Added unit tests and documented format and detection limitations.

## Try improving it

- Add support for IPv6 and more operating-system log formats.
- Add a time-window rule rather than counting the entire file.
- Include tests for malformed and unrelated lines.
