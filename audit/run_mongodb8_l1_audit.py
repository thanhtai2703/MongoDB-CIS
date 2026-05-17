#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/mongod.conf"

SECTIONS = [
    {"name": "1 - Software", "script": "audit_software.py"},
    {"name": "2 - Authentication", "script": "audit_authentication.py"},
    {"name": "3 - Authorization", "script": "audit_authorization.py"},
    {"name": "4 - Data Encryption", "script": "audit_data_encryption.py"},
    {"name": "6 - Network Configuration", "script": "audit_network_configuration.py"},
    {"name": "7 - File Permissions", "script": "audit_file_permissions.py"},
]


def run_section(script_path: Path, config_path: str, timeout: int = 90) -> dict[str, Any]:
    cmd = [sys.executable, str(script_path), "--config", config_path]

    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return section_error(script_path.name, cmd, 127, "", str(exc))
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
        return section_error(script_path.name, cmd, 124, stdout, "command timed out")

    if proc.returncode != 0:
        return section_error(script_path.name, cmd, proc.returncode, proc.stdout, proc.stderr)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return section_error(script_path.name, cmd, proc.returncode, proc.stdout, str(exc))


def section_error(
    script_name: str,
    cmd: list[str],
    rc: int,
    stdout: str,
    stderr: str,
) -> dict[str, Any]:
    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": script_name,
        "summary": {"ERROR": 1},
        "results": [
            {
                "control_id": "runner",
                "title": f"Run {script_name}",
                "assessment": "Automated",
                "status": "ERROR",
                "expected": "Section script runs and emits JSON",
                "actual": "Section script failed",
                "evidence": {
                    "cmd": " ".join(cmd),
                    "rc": rc,
                    "stdout": stdout.strip(),
                    "stderr": stderr.strip(),
                },
            }
        ],
    }


def aggregate_reports(section_reports: list[dict[str, Any]], config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    summary: dict[str, int] = {}
    sections: list[dict[str, Any]] = []

    for report in section_reports:
        section_name = report.get("section", "unknown")
        section_summary = report.get("summary", {})
        sections.append(
            {
                "section": section_name,
                "summary": section_summary,
            }
        )

        for item in report.get("results", []):
            enriched = dict(item)
            enriched["section"] = section_name
            results.append(enriched)

            status = str(enriched.get("status", "UNKNOWN"))
            summary[status] = summary.get(status, 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "profile": "Level 1 - MongoDB",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": summary,
        "sections": sections,
        "results": results,
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['benchmark']} - {report['profile']}",
        "",
        f"- Host: `{report['host']}`",
        f"- Generated: `{report['generated_at']}`",
        f"- Config: `{report['config_path']}`",
        f"- Summary: `{json.dumps(report['summary'], sort_keys=True)}`",
        "",
        "| Section | ID | Status | Assessment | Title | Actual |",
        "|---|---|---|---|---|---|",
    ]

    for item in report["results"]:
        actual = json.dumps(item.get("actual"), ensure_ascii=False)
        if len(actual) > 140:
            actual = actual[:137] + "..."
        lines.append(
            f"| {item.get('section', '')} | {item.get('control_id', '')} | "
            f"{item.get('status', '')} | {item.get('assessment', '')} | "
            f"{item.get('title', '')} | `{actual}` |"
        )

    lines.append("")
    lines.append("## Non-Pass Items")
    lines.append("")

    for item in report["results"]:
        if item.get("status") != "PASS":
            lines.append(
                f"- **{item.get('control_id')} {item.get('title')}** "
                f"({item.get('status')}, {item.get('section')}): "
                f"{json.dumps(item.get('actual'), ensure_ascii=False)}"
            )

    lines.append("")
    return "\n".join(lines)


def write_json(path: str, payload: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run split CIS MongoDB 8 Level 1 audit sections.")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to mongod.conf.")
    parser.add_argument("--output", default="", help="Write combined JSON report to this path.")
    parser.add_argument("--markdown", default="", help="Write combined Markdown report to this path.")
    parser.add_argument("--sections-dir", default="", help="Optional directory for per-section JSON reports.")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    section_reports = []

    sections_dir = Path(args.sections_dir) if args.sections_dir else None
    if sections_dir:
        sections_dir.mkdir(parents=True, exist_ok=True)

    for section in SECTIONS:
        report = run_section(base_dir / section["script"], args.config)
        section_reports.append(report)

        if sections_dir:
            section_file = section["name"].lower().replace(" ", "-").replace("/", "-")
            write_json(str(sections_dir / f"{section_file}.json"), report)

    combined = aggregate_reports(section_reports, args.config)
    payload = json.dumps(combined, indent=2, ensure_ascii=False)
    print(payload)

    if args.output:
        write_json(args.output, combined)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(markdown(combined))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
