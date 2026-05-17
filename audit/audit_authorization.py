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
DEFAULT_MONGO_PORT = 27017


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


def mongosh_eval(script: str, port: int) -> dict[str, Any]:
    user = os.environ.get("MONGO_AUDIT_USER", "")
    password = os.environ.get("MONGO_AUDIT_PASS", "")
    auth_db = os.environ.get("MONGO_AUDIT_AUTH_DB", "admin")
    host = os.environ.get("MONGO_AUDIT_HOST", "127.0.0.1")
    tls = os.environ.get("MONGO_AUDIT_TLS", "").lower() in {"1", "true", "yes", "enabled"}
    tls_ca_file = os.environ.get("MONGO_AUDIT_TLS_CA_FILE", "")
    tls_cert_key_file = os.environ.get("MONGO_AUDIT_TLS_CERT_KEY_FILE", "")
    tls_allow_invalid_hostnames = os.environ.get(
        "MONGO_AUDIT_TLS_ALLOW_INVALID_HOSTNAMES", ""
    ).lower() in {"1", "true", "yes"}

    cmd = ["mongosh", "--quiet", "--host", host, "--port", str(port)]

    if tls:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tlsCAFile", tls_ca_file])
    if tls_cert_key_file:
        cmd.extend(["--tlsCertificateKeyFile", tls_cert_key_file])
    if tls_allow_invalid_hostnames:
        cmd.append("--tlsAllowInvalidHostnames")

    if user:
        cmd.extend(["--username", user, "--password", password, "--authenticationDatabase", auth_db])

    cmd.extend(["--eval", script])
    result = run(cmd, timeout=20)

    if password:
        result["cmd"] = result["cmd"].replace(password, "********")

    return result


def check_3_1_least_privilege(results: list[dict[str, Any]], port: int) -> None:
    risky_roles = [
        "root",
        "dbOwner",
        "userAdmin",
        "userAdminAnyDatabase",
        "dbAdminAnyDatabase",
        "readWriteAnyDatabase",
    ]
    roles_json = json.dumps(risky_roles)
    query = (
        'JSON.stringify(db.getSiblingDB("admin").system.users.find('
        f'{{"roles.role":{{$in:{roles_json}}}}},'
        '{user:1,db:1,roles:1,_id:0}).toArray())'
    )
    risky_admin_roles = mongosh_eval(query, port)

    if risky_admin_roles["rc"] == 0:
        try:
            risky_users = json.loads(risky_admin_roles["stdout"] or "[]")
        except json.JSONDecodeError:
            risky_users = risky_admin_roles["stdout"]
        status = "PASS" if risky_users == [] else "FAIL"
        actual = risky_users
    else:
        status = "MANUAL"
        actual = "Unable to query users automatically"

    add_result(
        results,
        "3.1",
        "Ensure least privilege for database accounts",
        "Manual",
        status,
        "No normal account has broad administrative roles unless documented",
        actual,
        risky_admin_roles,
    )


def check_3_2_rbac_enabled(
    results: list[dict[str, Any]],
    conf: dict[str, Any],
    conf_error: str | None,
    config_path: str,
) -> None:
    authorization = get_path(conf, "security", "authorization")
    auth_enabled = str(authorization).lower() == "enabled"

    add_result(
        results,
        "3.2",
        "Ensure that role-based access control is enabled and configured appropriately",
        "Manual",
        "MANUAL" if auth_enabled else "FAIL",
        "RBAC is enabled and roles are reviewed against application needs",
        {"authorization": authorization},
        {
            "config": config_path,
            "config_error": conf_error,
            "note": "Role suitability still requires manual review.",
        },
    )


def check_3_3_non_root_service_user(results: list[dict[str, Any]]) -> None:
    systemctl_user = run(["systemctl", "show", "mongod", "-p", "User", "--value"])
    process_user = None
    ps_result: dict[str, Any] | None = None

    if systemctl_user["rc"] == 0 and systemctl_user["stdout"]:
        process_user = systemctl_user["stdout"]
    else:
        ps_result = run(["ps", "-eo", "user,comm,args"])
        for line in ps_result["stdout"].splitlines():
            if "mongod" in line and "grep" not in line:
                process_user = line.split()[0]
                break

    add_result(
        results,
        "3.3",
        "Ensure that MongoDB is run using a non-privileged, dedicated service account",
        "Automated",
        "PASS" if process_user and process_user != "root" else "FAIL",
        "mongod runs as a dedicated non-root account",
        process_user,
        {"systemctl": systemctl_user, "ps": ps_result},
    )


def check_3_4_role_privileges_review(results: list[dict[str, Any]], port: int) -> None:
    roles_info = mongosh_eval(
        'JSON.stringify(db.getSiblingDB("admin").runCommand('
        '{rolesInfo:1,showPrivileges:true,showBuiltinRoles:true}))',
        port,
    )

    add_result(
        results,
        "3.4",
        "Ensure that each role for each MongoDB database is needed and grants only the necessary privileges",
        "Manual",
        "MANUAL",
        "All roles and privileges are reviewed and documented",
        "Manual review required",
        roles_info,
    )


def audit(conf: dict[str, Any], conf_error: str | None, config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    port = int(get_path(conf, "net", "port", default=DEFAULT_MONGO_PORT) or DEFAULT_MONGO_PORT)

    check_3_1_least_privilege(results, port)
    check_3_2_rbac_enabled(results, conf, conf_error, config_path)
    check_3_3_non_root_service_user(results)
    check_3_4_role_privileges_review(results, port)

    counts: dict[str, int] = {}

    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "section": "3 - Authorization",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit CIS MongoDB 8 Section 3 - Authorization.")
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
