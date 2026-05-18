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


def normalize_protocols(value: Any) -> set[str]:
    if value is None:
        return set()

    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[, ]+", str(value))

    return {str(item).strip().upper() for item in items if str(item).strip()}


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

    tls_disabled = normalize_protocols(get_path(conf, "net", "tls", "disabledProtocols"))
    ssl_disabled = normalize_protocols(get_path(conf, "net", "ssl", "disabledProtocols"))

    disabled_protocols = tls_disabled or ssl_disabled

    add_result(
        results,
        "4.1",
        "Ensure legacy TLS protocols are disabled",
        "Automated",
        "PASS" if {"TLS1_0", "TLS1_1"}.issubset(disabled_protocols) else "FAIL",
        "disabledProtocols includes TLS1_0 and TLS1_1",
        sorted(disabled_protocols),
        {
            "net.tls.disabledProtocols": sorted(tls_disabled),
            "net.ssl.disabledProtocols": sorted(ssl_disabled),
            "config": config_path,
            "config_error": conf_error,
        },
    )

    add_result(
        results,
        "4.2",
        "Ensure Weak Protocols are Disabled",
        "Automated",
        "PASS" if {"TLS1_0", "TLS1_1"}.issubset(disabled_protocols) else "FAIL",
        "TLS1_0 and TLS1_1 are disabled",
        sorted(disabled_protocols),
        {
            "net.tls.disabledProtocols": sorted(tls_disabled),
            "net.ssl.disabledProtocols": sorted(ssl_disabled),
            "config": config_path,
            "config_error": conf_error,
        },
    )

    tls_mode = get_path(conf, "net", "tls", "mode")
    ssl_mode = get_path(conf, "net", "ssl", "mode")

    certificate_key_file = get_path(conf, "net", "tls", "certificateKeyFile")
    pem_key_file = get_path(conf, "net", "ssl", "PEMKeyFile")
    ca_file_tls = get_path(conf, "net", "tls", "CAFile")
    ca_file_ssl = get_path(conf, "net", "ssl", "CAFile")

    cert_file = certificate_key_file or pem_key_file
    ca_file = ca_file_tls or ca_file_ssl

    transport_ok = (
        str(tls_mode).lower() == "requiretls"
        or str(ssl_mode).lower() == "requiressl"
    ) and bool(cert_file) and bool(ca_file)

    add_result(
        results,
        "4.3",
        "Ensure Encryption of Data in Transit TLS or SSL",
        "Automated",
        "PASS" if transport_ok else "FAIL",
        "TLS/SSL mode is requireTLS/requireSSL and certificate + CA file are configured",
        {
            "tls_mode": tls_mode,
            "ssl_mode": ssl_mode,
            "certificateKeyFile": certificate_key_file,
            "PEMKeyFile": pem_key_file,
            "CAFile": ca_file,
        },
        {"config": config_path, "config_error": conf_error},
    )

    counts: dict[str, int] = {}

    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "4 - Data Encryption",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 4 - Data Encryption.")
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
