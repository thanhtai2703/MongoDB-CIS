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


def bool_false(value: Any) -> bool:
    if value is False:
        return True

    if isinstance(value, str) and value.lower() in {"false", "0", "disabled", "no"}:
        return True

    if isinstance(value, int) and value == 0:
        return True

    return False


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

    authorization = get_path(conf, "security", "authorization")

    add_result(
        results,
        "2.1",
        "Ensure Authentication is configured",
        "Automated",
        "PASS" if str(authorization).lower() == "enabled" else "FAIL",
        "security.authorization is enabled",
        authorization,
        {"config": config_path, "config_error": conf_error},
    )

    localhost_bypass = get_path(conf, "setParameter", "enableLocalhostAuthBypass")

    add_result(
        results,
        "2.2",
        "Ensure that MongoDB does not bypass authentication via the localhost exception",
        "Automated",
        "PASS" if bool_false(localhost_bypass) else "FAIL",
        "setParameter.enableLocalhostAuthBypass is false",
        localhost_bypass,
        {"config": config_path, "config_error": conf_error},
    )

    cluster_auth_mode = get_path(conf, "security", "clusterAuthMode")
    key_file = get_path(conf, "security", "keyFile")
    tls_cluster_file = get_path(conf, "net", "tls", "clusterFile")
    ssl_cluster_file = get_path(conf, "net", "ssl", "clusterFile")

    sharded_auth_ok = (
        str(cluster_auth_mode).lower() == "x509"
        or bool(key_file)
        or bool(tls_cluster_file)
        or bool(ssl_cluster_file)
    )

    add_result(
        results,
        "2.3",
        "Ensure authentication is enabled in the sharded cluster",
        "Automated",
        "PASS" if sharded_auth_ok else "FAIL",
        "clusterAuthMode is x509 or keyFile/clusterFile is configured",
        {
            "clusterAuthMode": cluster_auth_mode,
            "keyFile": key_file,
            "tls.clusterFile": tls_cluster_file,
            "ssl.clusterFile": ssl_cluster_file,
        },
        {"config": config_path, "config_error": conf_error},
    )

    counts: dict[str, int] = {}

    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "2 - Authentication",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 2 - Authentication.")
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