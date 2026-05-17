#!/usr/bin/env python3
"""
CIS MongoDB 8 Benchmark v1.0.0 Level 1 audit helper.

The script is intentionally dependency-free so Ansible can copy it to MongoDB
nodes and run it with the system Python. It reads /etc/mongod.conf, collects a
small amount of host evidence, and emits JSON plus an optional Markdown report.
"""

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
import subprocess
from typing import Any

try:
    import grp
    import pwd
except ImportError:  # Allows local syntax/smoke tests on Windows control hosts.
    grp = None
    pwd = None


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


def bool_false(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "disabled", "no"}:
        return True
    if isinstance(value, int) and value == 0:
        return True
    return False


def normalize_protocols(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[, ]+", str(value))
    return {str(item).strip().upper() for item in items if str(item).strip()}


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
    remediation: str,
) -> None:
    results.append(
        {
            "control_id": control_id,
            "title": title,
            "profile": "Level 1 - MongoDB",
            "assessment": assessment,
            "status": status,
            "expected": expected,
            "actual": actual,
            "evidence": evidence,
            "remediation": remediation,
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


def audit(conf: dict[str, Any], conf_error: str | None, config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    port = int(get_path(conf, "net", "port", default=DEFAULT_MONGO_PORT) or DEFAULT_MONGO_PORT)

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
        "Install an organization-approved MongoDB 8.x patch level for this benchmark, or use the benchmark matching the deployed major version.",
    )

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
        "Set security.authorization: enabled after creating the required admin and application users.",
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
        {"config": config_path},
        "Set setParameter.enableLocalhostAuthBypass: false in mongod.conf.",
    )

    risky_admin_roles = mongosh_eval(
        'JSON.stringify(db.getSiblingDB("admin").system.users.find('
        '{"roles.role":{$in:["dbOwner","userAdmin","userAdminAnyDatabase"]},"roles.db":"admin"},'
        '{user:1,roles:1,_id:0}).toArray())',
        port,
    )
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
        "No normal account has dbOwner, userAdmin, or userAdminAnyDatabase scoped to admin unless documented",
        actual,
        risky_admin_roles,
        "Review admin-scoped roles and remove unnecessary dbOwner/userAdmin/userAdminAnyDatabase assignments.",
    )

    auth_enabled = str(authorization).lower() == "enabled"
    add_result(
        results,
        "3.2",
        "Ensure that role-based access control is enabled and configured appropriately",
        "Manual",
        "MANUAL" if auth_enabled else "FAIL",
        "RBAC enabled and user roles reviewed against application needs",
        {"authorization": authorization},
        {"note": "RBAC suitability requires role review; script checks whether authorization is enabled."},
        "Define dedicated app/backup/admin roles and verify users only receive the roles they need.",
    )

    systemctl_user = run(["systemctl", "show", "mongod", "-p", "User", "--value"])
    process_user = None
    if systemctl_user["rc"] == 0 and systemctl_user["stdout"]:
        process_user = systemctl_user["stdout"]
    else:
        ps = run(["ps", "-eo", "user,comm,args"])
        for line in ps["stdout"].splitlines():
            if "mongod" in line and "grep" not in line:
                process_user = line.split()[0]
                break
    add_result(
        results,
        "3.3",
        "Ensure that MongoDB is run using a non-privileged, dedicated service account",
        "Manual",
        "PASS" if process_user and process_user != "root" else "FAIL",
        "mongod runs as a dedicated non-root account",
        process_user,
        {"systemctl": systemctl_user},
        "Run mongod under a dedicated non-root service account such as mongodb.",
    )

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
        "Review rolesInfo output and revoke privileges that are not required.",
    )

    tls_disabled = normalize_protocols(get_path(conf, "net", "tls", "disabledProtocols"))
    ssl_disabled = normalize_protocols(get_path(conf, "net", "ssl", "disabledProtocols"))
    disabled_protocols = tls_disabled or ssl_disabled
    add_result(
        results,
        "4.2",
        "Ensure Weak Protocols are Disabled",
        "Automated",
        "PASS" if {"TLS1_0", "TLS1_1"}.issubset(disabled_protocols) else "FAIL",
        "TLS1_0 and TLS1_1 are included in disabledProtocols",
        sorted(disabled_protocols),
        {"net.tls.disabledProtocols": list(tls_disabled), "net.ssl.disabledProtocols": list(ssl_disabled)},
        "Configure net.tls.disabledProtocols or net.ssl.disabledProtocols to include TLS1_0,TLS1_1.",
    )

    tls_mode = get_path(conf, "net", "tls", "mode")
    ssl_mode = get_path(conf, "net", "ssl", "mode")
    cert_file = get_path(conf, "net", "tls", "certificateKeyFile") or get_path(
        conf, "net", "ssl", "PEMKeyFile"
    )
    ca_file = get_path(conf, "net", "tls", "CAFile") or get_path(conf, "net", "ssl", "CAFile")
    transport_ok = str(tls_mode).lower() == "requiretls" or str(ssl_mode).lower() == "requiressl"
    transport_ok = transport_ok and bool(cert_file) and bool(ca_file)
    add_result(
        results,
        "4.3",
        "Ensure Encryption of Data in Transit TLS or SSL (Transport Encryption)",
        "Automated",
        "PASS" if transport_ok else "FAIL",
        "TLS/SSL mode requires encrypted transport and certificate/CA files are configured",
        {"tls_mode": tls_mode, "ssl_mode": ssl_mode, "certificateKeyFile": cert_file, "CAFile": ca_file},
        {"certificate": file_info(cert_file), "ca": file_info(ca_file)},
        "Set net.tls.mode: requireTLS with certificateKeyFile and CAFile, then update clients accordingly.",
    )

    audit_dest = get_path(conf, "auditLog", "destination")
    audit_format = get_path(conf, "auditLog", "format")
    audit_path = get_path(conf, "auditLog", "path")
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
        {"destination": audit_dest, "format": audit_format, "path": audit_path},
        {"note": "MongoDB Community may not support enterprise audit logging; document exception if applicable."},
        "Configure auditLog.destination and related audit settings, or document a product-edition exception.",
    )

    add_result(
        results,
        "6.1",
        "Ensure that MongoDB uses a non-default port",
        "Automated",
        "PASS" if port != DEFAULT_MONGO_PORT else "FAIL",
        "MongoDB listens on an organization-defined non-default port",
        port,
        {"default_port": DEFAULT_MONGO_PORT},
        "Set net.port to an approved non-default port and update replica set, app, backup, and firewall configuration.",
    )

    key_file = get_path(conf, "security", "keyFile")
    key_info = file_info(key_file)
    key_ok = (
        bool(key_file)
        and key_info.get("exists") is True
        and key_info.get("owner") == "mongodb"
        and int(key_info.get("mode_int", 0)) <= 0o600
    )
    add_result(
        results,
        "7.1",
        "Ensure appropriate key file permissions are set",
        "Manual",
        "PASS" if key_ok else "FAIL",
        "security.keyFile exists, is owned by mongodb, and is not more permissive than 0600",
        key_info,
        {"security.keyFile": key_file},
        "Create a replica-set keyFile, chown mongodb:mongodb, chmod 600, and reference it in mongod.conf.",
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
        "Manual",
        "PASS" if db_ok else "FAIL",
        "database path is owned by mongodb:mongodb with mode 0770",
        db_info,
        {"storage.dbPath": db_path},
        "Run chown mongodb:mongodb on the database path and set permissions to 0770.",
    )

    counts: dict[str, int] = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1

    return {
        "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
        "profile": "Level 1 - MongoDB",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": platform.platform(),
        "config_path": config_path,
        "summary": counts,
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
        "| ID | Status | Assessment | Title | Actual |",
        "|---|---|---|---|---|",
    ]
    for item in report["results"]:
        actual = json.dumps(item["actual"], ensure_ascii=False)
        if len(actual) > 140:
            actual = actual[:137] + "..."
        lines.append(
            f"| {item['control_id']} | {item['status']} | {item['assessment']} | "
            f"{item['title']} | `{actual}` |"
        )
    lines.append("")
    lines.append("## Remediation Hints")
    lines.append("")
    for item in report["results"]:
        if item["status"] != "PASS":
            lines.append(f"- **{item['control_id']} {item['title']}**: {item['remediation']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit MongoDB against CIS MongoDB 8 L1 controls.")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to mongod.conf.")
    parser.add_argument("--output", default="", help="Write JSON report to this path.")
    parser.add_argument("--markdown", default="", help="Write Markdown report to this path.")
    args = parser.parse_args()

    conf, conf_error = parse_mongod_conf(args.config)
    report = audit(conf, conf_error, args.config)
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    print(payload)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
