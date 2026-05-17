#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import platform
import re
import socket
import subprocess
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/mongod.conf"


def run(cmd: list[str], timeout: int = 12) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "cmd": " ".join(cmd),
            "rc": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {"cmd": " ".join(cmd), "rc": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": " ".join(cmd),
            "rc": 124,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": "command timed out",
        }


def add_result(
    results: list[dict[str, Any]],
    control_id: str,
    title: str,
    assessment: str,
    status: str,
    expected: str,
    actual: Any,
    evidence: Any,
) -> None:
    results.append(
        {
            "control_id": control_id,
            "title": title,
            "assessment": assessment,
            "status": status,
            "expected": expected,
            "actual": actual,
            "evidence": evidence,
        }
    )


def audit(config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    version_cmd = run(["mongod", "--version"])
    version_text = version_cmd["stdout"] or version_cmd["stderr"]
    version_match = re.search(r"db version v?(\d+\.\d+\.\d+)", version_text)
    version = version_match.group(1) if version_match else "unknown"

    add_result(
        results,
        "1.1",
        "Ensure the appropriate MongoDB software version/patches are installed",
        "Manual",
        "PASS" if version.startswith("8.") else "FAIL",
        "MongoDB 8.x with organization-approved patch level",
        version,
        version_cmd,
    )

    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "1 - Software",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 1 - Software.")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to mongod.conf.")
    parser.add_argument("--output", default="", help="Write JSON report to this path.")
    args = parser.parse_args()

    report = audit(args.config)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    print(payload)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
