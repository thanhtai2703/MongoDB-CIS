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
import stat
from typing import Any

try:
    import grp
    import pwd
except ImportError:
    grp = None
    pwd = None


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


def owner_name(uid: int) -> str:
    if pwd is None:
        return str(uid)
    return pwd.getpwuid(uid).pw_name


def group_name(gid: int) -> str:
    if grp is None:
        return str(gid)
    return grp.getgrgid(gid).gr_name


def file_info(path: str | None) -> dict[str, Any]:
    if not path:
        return {"exists": False, "path": path}

    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {"exists": False, "path": path}

    return {
        "exists": True,
        "path": path,
        "mode": oct(stat.S_IMODE(st.st_mode)),
        "mode_int": stat.S_IMODE(st.st_mode),
        "owner": owner_name(st.st_uid),
        "group": group_name(st.st_gid),
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


def check_secret_file(path: str | None, max_mode: int) -> tuple[bool, dict[str, Any]]:
    info = file_info(path)
    if not path:
        return False, info
    ok = (
        info.get("exists") is True
        and info.get("owner") == "mongodb"
        and int(info.get("mode_int", 0)) <= max_mode
    )
    return ok, info


def check_public_file(path: str | None, max_mode: int) -> tuple[bool, dict[str, Any]]:
    info = file_info(path)
    if not path:
        return False, info
    ok = (
        info.get("exists") is True
        and info.get("owner") in {"mongodb", "root"}
        and int(info.get("mode_int", 0)) <= max_mode
    )
    return ok, info


def audit(conf: dict[str, Any], conf_error: str | None, config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    key_file = get_path(conf, "security", "keyFile")
    cert_key_file = (
        get_path(conf, "net", "tls", "certificateKeyFile")
        or get_path(conf, "net", "ssl", "PEMKeyFile")
    )
    ca_file = (
        get_path(conf, "net", "tls", "CAFile")
        or get_path(conf, "net", "ssl", "CAFile")
    )

    key_ok, key_info = check_secret_file(key_file, 0o600)
    cert_ok, cert_info = check_secret_file(cert_key_file, 0o600)
    ca_ok, ca_info = check_public_file(ca_file, 0o644)

    configured_files = [
        ("security.keyFile", key_file, key_ok, key_info, "<= 0600, owner=mongodb"),
        ("net.tls.certificateKeyFile", cert_key_file, cert_ok, cert_info, "<= 0600, owner=mongodb"),
        ("net.tls.CAFile", ca_file, ca_ok, ca_info, "<= 0644, owner in {mongodb, root}"),
    ]

    file_evidence = [
        {
            "setting": setting,
            "path": path,
            "info": info,
            "ok": ok,
            "expected_mode": expected,
        }
        for setting, path, ok, info, expected in configured_files
    ]

    present_files = [item for item in file_evidence if item["path"]]
    overall_ok = bool(present_files) and all(item["ok"] for item in present_files)

    add_result(
        results,
        "7.1",
        "Ensure appropriate key file permissions are set",
        "Automated",
        "PASS" if overall_ok else "FAIL",
        "security.keyFile, net.tls.certificateKeyFile (mode<=0600) and net.tls.CAFile (mode<=0644) are owned by mongodb and not more permissive than required",
        file_evidence,
        {
            "config": config_path,
            "config_error": conf_error,
        },
    )

    db_path = get_path(conf, "storage", "dbPath", default="/var/lib/mongodb")
    db_info = file_info(db_path)
    db_ok = (
        db_info.get("exists") is True
        and db_info.get("owner") == "mongodb"
        and db_info.get("group") == "mongodb"
        and db_info.get("mode_int") == 0o770
    )

    add_result(
        results,
        "7.2",
        "Ensure appropriate database file permissions are set",
        "Automated",
        "PASS" if db_ok else "FAIL",
        "database path is owned by mongodb:mongodb with mode 0770",
        db_info,
        {
            "storage.dbPath": db_path,
            "config": config_path,
            "config_error": conf_error,
        },
    )

    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "7 - File Permissions",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 7 - File Permissions.")
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
