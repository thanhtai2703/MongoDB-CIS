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
    allowed_admin_users = {
        user.strip()
        for user in os.environ.get("MONGO_AUDIT_ALLOWED_ADMIN_USERS", "").split(",")
        if user.strip()
    }
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
        if isinstance(risky_users, list):
            undocumented_users = [
                user
                for user in risky_users
                if str(user.get("user", "")) not in allowed_admin_users
            ]
            status = "PASS" if undocumented_users == [] else "FAIL"
            actual = {
                "undocumented_broad_role_users": undocumented_users,
                "documented_admin_users": [
                    user
                    for user in risky_users
                    if str(user.get("user", "")) in allowed_admin_users
                ],
            }
        else:
            status = "FAIL"
            actual = risky_users
    else:
        status = "FAIL"
        actual = "Unable to query users automatically (mongosh failed)"

    add_result(
        results,
        "3.1",
        "Ensure least privilege for database accounts",
        "Manual",
        status,
        "No normal account has broad administrative roles unless documented",
        actual,
        {
            "query": risky_admin_roles,
            "allowed_admin_users": sorted(allowed_admin_users),
        },
    )


def check_3_2_rbac_enabled(
    results: list[dict[str, Any]],
    conf: dict[str, Any],
    conf_error: str | None,
    config_path: str,
    port: int,
) -> None:
    authorization = get_path(conf, "security", "authorization")
    auth_enabled = str(authorization).lower() == "enabled"

    if not auth_enabled:
        add_result(
            results,
            "3.2",
            "Ensure that role-based access control is enabled and configured appropriately",
            "Manual",
            "FAIL",
            "RBAC is enabled (security.authorization=enabled) before reviewing roles",
            {"authorization": authorization},
            {"config": config_path, "config_error": conf_error},
        )
        return

    allowed_admin_users = {
        user.strip()
        for user in os.environ.get("MONGO_AUDIT_ALLOWED_ADMIN_USERS", "").split(",")
        if user.strip()
    }
    privileged_roles = {
        "root",
        "dbOwner",
        "userAdmin",
        "userAdminAnyDatabase",
        "dbAdminAnyDatabase",
        "readWriteAnyDatabase",
        "clusterAdmin",
        "hostManager",
        "backup",
        "restore",
    }

    users_query = mongosh_eval(
        'JSON.stringify(db.getSiblingDB("admin").system.users.find('
        '{}, {user:1, db:1, roles:1, _id:0}).toArray())',
        port,
    )

    evidence: Any = {
        "config": config_path,
        "config_error": conf_error,
        "query": users_query,
        "allowed_admin_users": sorted(allowed_admin_users),
        "privileged_roles_checked": sorted(privileged_roles),
    }

    if users_query["rc"] != 0:
        add_result(
            results,
            "3.2",
            "Ensure that role-based access control is enabled and configured appropriately",
            "Manual",
            "FAIL",
            "Each user has roles assigned, and only allowed admin users hold privileged roles",
            "Unable to enumerate users (mongosh failed)",
            evidence,
        )
        return

    try:
        users_list = json.loads(users_query["stdout"] or "[]")
    except json.JSONDecodeError:
        evidence["stdout_parse_error"] = users_query["stdout"]
        users_list = []

    violations: list[dict[str, Any]] = []
    user_summaries: list[dict[str, Any]] = []

    for user in users_list:
        if not isinstance(user, dict):
            continue
        username = str(user.get("user", ""))
        user_roles = [
            {"role": r.get("role"), "db": r.get("db")}
            for r in (user.get("roles") or [])
            if isinstance(r, dict)
        ]
        user_summaries.append(
            {"user": username, "auth_db": str(user.get("db", "")), "roles": user_roles}
        )

        if not user_roles:
            violations.append({"user": username, "issue": "no roles assigned", "roles": []})
            continue

        if username in allowed_admin_users:
            continue

        bad_roles = [
            r for r in user_roles if str(r.get("role")) in privileged_roles
        ]
        if bad_roles:
            violations.append(
                {
                    "user": username,
                    "issue": "non-allowed user holds privileged role",
                    "roles": bad_roles,
                }
            )

    status = "PASS" if not violations else "FAIL"
    actual: Any = {
        "authorization": authorization,
        "user_count": len(user_summaries),
        "violations": violations,
        "users": user_summaries,
    }

    add_result(
        results,
        "3.2",
        "Ensure that role-based access control is enabled and configured appropriately",
        "Manual",
        status,
        "All users have at least one role and only allowed admins hold privileged roles",
        actual,
        evidence,
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


def role_names(roles: Any) -> list[str]:
    names: list[str] = []

    if not isinstance(roles, list):
        return names

    for item in roles:
        if isinstance(item, dict):
            role = item.get("role")
        else:
            role = item

        if role is not None:
            names.append(str(role))

    return names


def privilege_has_any_resource(privileges: Any) -> bool:
    if not isinstance(privileges, list):
        return False

    for privilege in privileges:
        if not isinstance(privilege, dict):
            continue

        resource = privilege.get("resource", {})
        if isinstance(resource, dict) and resource.get("anyResource") is True:
            return True

    return False


def summarize_custom_role(role: dict[str, Any]) -> dict[str, Any]:
    inherited_role_names = sorted(set(role_names(role.get("inheritedRoles")) + role_names(role.get("roles"))))
    privilege_count = len(role.get("privileges") or [])
    inherited_privilege_count = len(role.get("inheritedPrivileges") or [])
    has_any_resource = privilege_has_any_resource(role.get("privileges")) or privilege_has_any_resource(
        role.get("inheritedPrivileges")
    )
    dangerous_inherited_roles = [
        role_name for role_name in inherited_role_names if role_name in {"root", "dbOwner"}
    ]

    summary = {
        "db": role.get("db"),
        "role": role.get("role"),
        "inherited_roles": inherited_role_names,
        "privilege_count": privilege_count,
        "inherited_privilege_count": inherited_privilege_count,
        "has_anyResource": has_any_resource,
    }

    if dangerous_inherited_roles:
        summary["dangerous_inherited_roles"] = dangerous_inherited_roles

    return summary


def check_3_4_role_privileges_review(results: list[dict[str, Any]], port: int) -> None:
    custom_roles_result = mongosh_eval(
        """
        const customRoles = [];
        const dbList = db.adminCommand({ listDatabases: 1 });
        if (dbList.ok === 1 && Array.isArray(dbList.databases)) {
          dbList.databases.forEach(function(dbInfo) {
            const targetDb = db.getSiblingDB(dbInfo.name);
            const rolesResult = targetDb.runCommand({
              rolesInfo: 1,
              showPrivileges: true,
              showBuiltinRoles: false
            });
            if (rolesResult.ok === 1 && Array.isArray(rolesResult.roles)) {
              rolesResult.roles.forEach(function(role) {
                customRoles.push(role);
              });
            }
          });
        }
        JSON.stringify(customRoles);
        """,
        port,
    )

    status = "FAIL"
    actual: Any = "Unable to query custom roles automatically"
    evidence: Any = {
        "cmd": custom_roles_result["cmd"],
        "rc": custom_roles_result["rc"],
        "stdout": custom_roles_result["stdout"],
        "stderr": custom_roles_result["stderr"],
    }

    if custom_roles_result["rc"] == 0:
        try:
            custom_roles = json.loads(custom_roles_result["stdout"] or "[]")
        except json.JSONDecodeError:
            custom_roles = []
            evidence["stdout_parse_error"] = custom_roles_result["stdout"]

        role_summaries = [
            summarize_custom_role(role)
            for role in custom_roles
            if isinstance(role, dict)
        ]
        dangerous_roles = [
            role
            for role in role_summaries
            if role["has_anyResource"] or role.get("dangerous_inherited_roles")
        ]

        evidence.update(
            {
                "custom_role_count": len(role_summaries),
                "custom_roles": role_summaries,
                "dangerous_roles": dangerous_roles,
            }
        )

        if dangerous_roles:
            status = "FAIL"
            actual = {
                "dangerous_role_count": len(dangerous_roles),
                "dangerous_roles": dangerous_roles,
            }
        else:
            status = "PASS"
            actual = (
                "No custom roles found"
                if not role_summaries
                else {
                    "custom_role_count": len(role_summaries),
                    "custom_roles": role_summaries,
                    "note": "All custom roles are scoped (no anyResource, no inherited root/dbOwner).",
                }
            )

    add_result(
        results,
        "3.4",
        "Ensure that each role for each MongoDB database is needed and grants only the necessary privileges",
        "Manual",
        status,
        "No dangerous custom role uses anyResource or inherits root/dbOwner",
        actual,
        evidence,
    )


def audit(conf: dict[str, Any], conf_error: str | None, config_path: str) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    port = int(get_path(conf, "net", "port", default=DEFAULT_MONGO_PORT) or DEFAULT_MONGO_PORT)

    check_3_1_least_privilege(results, port)
    check_3_2_rbac_enabled(results, conf, conf_error, config_path, port)
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
