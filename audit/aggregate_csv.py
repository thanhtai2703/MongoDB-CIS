#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import sys
from pathlib import Path
from typing import Any


def load_reports(directory: str) -> dict[str, dict[str, Any]]:
    reports = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        host = Path(path).stem
        with open(path, "r", encoding="utf-8") as f:
            reports[host] = json.load(f)
    return reports


def truncate(value: Any, limit: int = 80) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def build_pivot(reports: dict[str, dict[str, Any]]) -> tuple[list[str], list[dict[str, str]]]:
    hosts = list(reports.keys())
    control_index: dict[str, dict[str, str]] = {}

    for host, report in reports.items():
        for item in report.get("results", []):
            cid = str(item.get("control_id", ""))
            if cid not in control_index:
                control_index[cid] = {
                    "section": str(item.get("section", "")),
                    "control_id": cid,
                    "title": str(item.get("title", "")),
                    "assessment": str(item.get("assessment", "")),
                    "expected": str(item.get("expected", "")),
                }
            control_index[cid][f"{host}_status"] = str(item.get("status", ""))
            control_index[cid][f"{host}_actual"] = truncate(item.get("actual"))

    fieldnames = ["section", "control_id", "title", "assessment", "expected"]
    for host in hosts:
        fieldnames.extend([f"{host}_status", f"{host}_actual"])
    fieldnames.append("overall")

    rows = []
    for cid in sorted(control_index.keys(), key=lambda x: [int(p) if p.isdigit() else p for p in x.split(".")]):
        row = control_index[cid]
        statuses = [row.get(f"{h}_status", "") for h in hosts]
        if statuses and all(s == "PASS" for s in statuses):
            row["overall"] = "PASS"
        elif any(s == "FAIL" for s in statuses):
            row["overall"] = "FAIL"
        elif any(s == "ERROR" for s in statuses):
            row["overall"] = "ERROR"
        elif any(s == "REVIEW" for s in statuses):
            row["overall"] = "REVIEW"
        else:
            row["overall"] = "UNKNOWN"
        rows.append(row)

    return fieldnames, rows


def build_long(reports: dict[str, dict[str, Any]]) -> tuple[list[str], list[dict[str, str]]]:
    fieldnames = ["host", "section", "control_id", "title", "assessment", "status", "expected", "actual"]
    rows = []
    for host, report in reports.items():
        for item in report.get("results", []):
            rows.append({
                "host": host,
                "section": str(item.get("section", "")),
                "control_id": str(item.get("control_id", "")),
                "title": str(item.get("title", "")),
                "assessment": str(item.get("assessment", "")),
                "status": str(item.get("status", "")),
                "expected": str(item.get("expected", "")),
                "actual": truncate(item.get("actual")),
            })
    return fieldnames, rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate CIS audit JSON reports into a single CSV.")
    parser.add_argument("directory", help="Directory containing per-host audit JSON files (e.g. reports/before).")
    parser.add_argument("--output", "-o", default="", help="Output CSV path (default: <directory>.csv).")
    parser.add_argument("--format", choices=["pivot", "long"], default="pivot",
                        help="pivot: one row per control with one column per host (default). "
                             "long: one row per (host, control).")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"error: directory not found: {args.directory}", file=sys.stderr)
        return 1

    reports = load_reports(args.directory)
    if not reports:
        print(f"error: no JSON reports in {args.directory}", file=sys.stderr)
        return 1

    if args.format == "pivot":
        fieldnames, rows = build_pivot(reports)
    else:
        fieldnames, rows = build_long(reports)

    output = args.output or args.directory.rstrip("/\\") + ".csv"
    with open(output, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} rows from {len(reports)} hosts to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
