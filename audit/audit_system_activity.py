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
from typing import Any

DEFAULT_CONFIG_PATH = "/etc/mongod.conf"


def strip_comment(line: str) -> str:
    in_single = False
    in_double = False

    for idx, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:idx]

    return line


def parse_scalar(value: str) -> Any:
    value = value.strip()

    if value == "":
        return ""

    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    lowered = value.lower()

    if lowered in {"true", "yes"}:
        return True

    if lowered in {"false", "no"}:
        return False

    if lowered in {"null", "none"}:
        return None

    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            return value

    return value


def parse_mongod_conf(path: str) -> tuple[dict[str, Any], str | None]:
    if not os.path.exists(path):
        return {}, f"{path} not found"

    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = strip_comment(raw.rstrip("\n"))

            if not line.strip():
                continue

            indent = len(line) - len(line.lstrip(" "))
            item = line.strip()

            if ":" not in item:
                continue

            key, value = item.split(":", 1)
            key = key.strip()
            value = value.strip()

            while stack and indent <= stack[-1][0]:
                stack.pop()

            parent = stack[-1][1]

            if value == "":
                child: dict[str, Any] = {}
                parent[key] = child
                stack.append((indent, child))
            else:
                parent[key] = parse_scalar(value)

    return root, None


def get_path(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data

    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]

    return cur


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


def audit(conf: dict[str, Any], conf_error: str | None, config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    audit_dest = get_path(conf, "auditLog", "destination")
    audit_format = get_path(conf, "auditLog", "format")
    audit_path = get_path(conf, "auditLog", "path")
    audit_filter = get_path(conf, "auditLog", "filter")
    audit_ok = bool(audit_dest) and (
        audit_dest in {"syslog", "console"} or (audit_dest == "file" and bool(audit_format) and bool(audit_path))
    )

    add_result(
        results,
        "5.1",
        "Ensure that system activity is audited",
        "Automated",
        "PASS" if audit_ok else "FAIL",
        "auditLog.destination is configured; file destinations also define format and path",
        {
            "destination": audit_dest,
            "format": audit_format,
            "path": audit_path,
            "filter": audit_filter,
        },
        {
            "config": config_path,
            "config_error": conf_error,
            "note": "MongoDB Community may not support enterprise audit logging; document exception if applicable.",
        },
    )

    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "5 - Auditing",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 5 - Auditing.")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to mongod.conf.")
    parser.add_argument("--output", default="", help="Write JSON report to this path.")
    args = parser.parse_args()

    conf, conf_error = parse_mongod_conf(args.config)
    report = audit(conf, conf_error, args.config)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    print(payload)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
