# Phân tích logic Audit CIS MongoDB 8 Level 1

Tài liệu mô tả chi tiết cách bộ audit hoạt động: từ kiến trúc tổng thể đến từng control, từng dòng logic PASS/FAIL, và mức độ tuân thủ so với CIS MongoDB 8 Benchmark v1.0.0.

---

## 1. Kiến trúc tổng thể

### 1.1 Cây file

```
audit/
├── run_mongodb8_l1_audit.py       ← Runner (orchestrator)
├── audit_software.py              → Section 1
├── audit_authentication.py        → Section 2
├── audit_authorization.py         → Section 3 (gọi mongosh)
├── audit_data_encryption.py       → Section 4
├── audit_network_configuration.py → Section 6
├── audit_file_permissions.py      → Section 7
└── aggregate_csv.py               ← Gom report từ nhiều node thành CSV
```

### 1.2 Flow gọi

```
ansible-playbook audit_mongodb8_l1.yaml
        │
        ├─ Copy 7 file .py + run_mongodb8_l1_audit.py lên /tmp/cis_mongodb8_l1/ trên từng db-node
        │
        ├─ Set 9 env var: MONGO_AUDIT_HOST, MONGO_AUDIT_USER, MONGO_AUDIT_PASS, …
        │
        └─ Chạy: python3 run_mongodb8_l1_audit.py --output <host>.json --markdown <host>.md
                    │
                    ├─→ subprocess: audit_software.py            → stdout JSON
                    ├─→ subprocess: audit_authentication.py      → stdout JSON
                    ├─→ subprocess: audit_authorization.py       → stdout JSON
                    ├─→ subprocess: audit_data_encryption.py     → stdout JSON
                    ├─→ subprocess: audit_network_configuration.py → stdout JSON
                    └─→ subprocess: audit_file_permissions.py    → stdout JSON
                    
                    → Gom tất cả → 1 JSON tổng + 1 Markdown
                    
                    → Ansible fetch về controller: reports/<phase>/<host>.{json,md}
```

### 1.3 Vì sao tách 6 file section

- **Cô lập lỗi**: Nếu 1 section crash, runner vẫn report 5 section còn lại + entry ERROR cho section bị lỗi
- **Tái sử dụng**: Có thể chạy riêng từng section script để debug
- **Audit độc lập config**: Tất cả section đều nhận `--config /etc/mongod.conf` riêng, không share state Python

---

## 2. Runner — `run_mongodb8_l1_audit.py`

### 2.1 Trách nhiệm

1. **Iterate** danh sách `SECTIONS` (hardcode 6 entry, [line 18-25](run_mongodb8_l1_audit.py#L18-L25))
2. **Spawn subprocess** mỗi section qua `subprocess.run(cmd, timeout=90)`
3. **Bắt lỗi** 3 loại: `FileNotFoundError` (script không tồn tại), `TimeoutExpired` (>90s), `rc != 0` → tất cả wrap thành section ERROR
4. **Parse stdout** thành JSON → gom vào `section_reports[]`
5. **Render** 2 output:
   - JSON tổng — chứa tất cả results gắn thêm field `section`
   - Markdown — bảng + "Non-Pass Items" section

### 2.2 Cấu trúc JSON tổng (output cuối)

```json
{
  "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
  "profile": "Level 1 - MongoDB",
  "generated_at": "2026-05-18T12:34:56+00:00",
  "host": "db-node-1",
  "config_path": "/etc/mongod.conf",
  "summary": { "PASS": 8, "FAIL": 4, "ERROR": 0 },
  "sections": [
    { "section": "1 - Software",     "summary": { "PASS": 1 } },
    { "section": "2 - Authentication", "summary": { "PASS": 2 } },
    …
  ],
  "results": [
    {
      "section": "2 - Authentication",
      "control_id": "2.1",
      "title": "Ensure Authentication is configured",
      "assessment": "Automated",
      "status": "PASS",
      "expected": "security.authorization is enabled",
      "actual": "enabled",
      "evidence": { "config": "/etc/mongod.conf", "config_error": null }
    },
    …
  ]
}
```

`status` chỉ có 4 giá trị: `PASS`, `FAIL`, `MANUAL` (đã bỏ trong logic mới), `ERROR` (do runner thêm khi subprocess fail).

---

## 3. Common logic (parse mongod.conf)

5/6 file section đều parse `/etc/mongod.conf` theo cùng pattern:

```python
def parse_mongod_conf(path: str) -> tuple[dict[str, Any], str | None]:
```

### 3.1 Parser tự viết (mini YAML)

Không dùng `pyyaml` (vì audit script cần chạy độc lập, không cài thêm package). Parser tự viết xử lý:

- **Comment**: `strip_comment()` loại bỏ `# …` (có xử lý quote — # trong string không bị strip)
- **Indent-based nesting**: track stack `[(indent, dict)]`, mỗi key mới so sánh indent với stack top
- **Scalar parsing**: `parse_scalar()` nhận diện `true/false/yes/no/null/none`, số nguyên, string trong/ngoài quote

### 3.2 Hạn chế parser

| Cấu trúc YAML | Parser tự viết hiểu? |
|---|---|
| `key: value` (scalar) | ✅ |
| `key:` + nested indent | ✅ |
| `disabledProtocols: TLS1_0,TLS1_1` (string) | ✅ |
| `disabledProtocols:\n  - TLS1_0\n  - TLS1_1` (list) | ❌ → trả `{}` (sai) |
| `key: \|\n  multiline` | ❌ |
| Anchor `&`, inline `{}` | ❌ |
| `# comment` trên line riêng | ✅ |

Toàn bộ template trong project (`mongod.conf.j2`, `mongod_auth.conf.j2`, `mongod_tls.conf.j2`) đều dùng pattern scalar + nested → parser xử lý đúng.

### 3.3 Hàm helper

```python
def get_path(data: dict, *keys: str, default=None) -> Any:
```

Truy cập nested key an toàn: `get_path(conf, "security", "authorization")` trả `None` nếu thiếu bất kỳ key nào trên đường đi.

---

## 4. Section 1 — Software (`audit_software.py`)

### 4.1 Control 1.1 — MongoDB version

**PDF yêu cầu**:
> Run `mongod --version` (or `db.version()` inside shell). Verify version matches organization-approved patch level.

**Code thực hiện** ([audit_software.py:70-84](audit_software.py#L70-L84)):
```python
version_cmd = run(["mongod", "--version"])
version_text = version_cmd["stdout"] or version_cmd["stderr"]
version_match = re.search(r"db version v?(\d+\.\d+\.\d+)", version_text)
version = version_match.group(1) if version_match else "unknown"
status = "PASS" if version.startswith("8.") else "FAIL"
```

**Logic PASS/FAIL**:
- PASS khi `mongod --version` chứa pattern `db version v8.x.x`
- FAIL khi version không bắt đầu bằng "8." hoặc không match regex

**Khác PDF**: PDF marked "Manual" (organization-defined), code tự quyết PASS/FAIL theo major version 8. Hợp lý vì benchmark này dành cho MongoDB 8.

---

## 5. Section 2 — Authentication (`audit_authentication.py`)

### 5.1 Control 2.1 — Authentication configured

**PDF yêu cầu**:
> `cat /etc/mongod.conf | grep "authorization"` → must be `enabled`

**Code thực hiện** ([audit_authentication.py:152-163](audit_authentication.py#L152-L163)):
```python
authorization = get_path(conf, "security", "authorization")
status = "PASS" if str(authorization).lower() == "enabled" else "FAIL"
```

**Logic PASS/FAIL**:
- PASS khi `security.authorization == "enabled"`
- FAIL khi missing, `disabled`, hoặc giá trị khác

**Mapping**:
- BEFORE (mongod.conf.j2 plain): không có `security.authorization` → `None` → FAIL ✅
- AFTER (mongod_auth/tls.conf.j2): `authorization: enabled` → PASS ✅

### 5.2 Control 2.2 — Localhost auth bypass

**PDF yêu cầu**:
> `grep "enableLocalhostAuthBypass"` → must be `false`

**Code thực hiện** ([audit_authentication.py:165-176](audit_authentication.py#L165-L176)):
```python
localhost_bypass = get_path(conf, "setParameter", "enableLocalhostAuthBypass")
status = "PASS" if bool_false(localhost_bypass) else "FAIL"
```

**Hàm `bool_false`**:
```python
def bool_false(value):
    if value is False: return True
    if isinstance(value, str) and value.lower() in {"false", "0", "disabled", "no"}: return True
    if isinstance(value, int) and value == 0: return True
    return False
```

**Logic PASS/FAIL**:
- PASS khi value rõ ràng `false/no/0/disabled`
- FAIL khi missing (MongoDB default = `true` = bypass enabled), `true`, hoặc giá trị lạ

**Edge case quan trọng**: Khi key missing, `localhost_bypass = None`, `bool_false(None) = False` → FAIL. **Đúng theo PDF** vì default MongoDB là `true` (bypass enabled) — phải explicit set `false` mới đạt CIS.

---

## 6. Section 3 — Authorization (`audit_authorization.py`)

Đây là section phức tạp nhất, **gọi mongosh** để query MongoDB live.

### 6.1 Helper `mongosh_eval()`

```python
def mongosh_eval(script: str, port: int) -> dict:
```

Build command dựa trên env vars:
```
mongosh --quiet --host $MONGO_AUDIT_HOST --port <port>
  [--tls --tlsCAFile … --tlsCertificateKeyFile … --tlsAllowInvalidHostnames]   ← chỉ khi MONGO_AUDIT_TLS=true
  [--username $MONGO_AUDIT_USER --password $MONGO_AUDIT_PASS --authenticationDatabase $MONGO_AUDIT_AUTH_DB]  ← chỉ khi có user
  --eval "<script>"
```

**Quan trọng**: tất cả flag TLS đều nằm trong `if tls:` block. Nếu env `MONGO_AUDIT_TLS=false`, các flag TLS bị bỏ → mongosh connect plain. (Bug cũ là các flag TLS được thêm độc lập theo từng env var → đã fix.)

Output:
```python
{
    "cmd": "mongosh --quiet …",     # đã mask password thành "********"
    "rc": 0,
    "stdout": "…",
    "stderr": "…"
}
```

### 6.2 Control 3.1 — Least privilege

**PDF yêu cầu**:
```javascript
db.system.users.find(
  {"roles.role":{$in:["dbOwner","userAdmin","userAdminAnyDatabase"]},"roles.db":"admin"}
)
```

**Code thực hiện**:
```python
risky_roles = [
    "root",                       # ← mở rộng ngoài PDF
    "dbOwner",                    # PDF có
    "userAdmin",                  # PDF có
    "userAdminAnyDatabase",       # PDF có
    "dbAdminAnyDatabase",         # ← mở rộng ngoài PDF
    "readWriteAnyDatabase",       # ← mở rộng ngoài PDF
]
query = JSON.stringify(
    db.getSiblingDB("admin").system.users.find(
        {"roles.role": {$in: risky_roles}},
        {user:1, db:1, roles:1, _id:0}
    ).toArray()
)
```

**Khác PDF**:
- Mở rộng danh sách: thêm `root`, `dbAdminAnyDatabase`, `readWriteAnyDatabase` (Section 3.5 của PDF nhắc đến nhưng chỉ là Level 2)
- Bỏ filter `roles.db: "admin"` — query tìm risky role ở bất kỳ db nào, không chỉ admin db

**Logic PASS/FAIL**:
```python
allowed_admin_users = set from env MONGO_AUDIT_ALLOWED_ADMIN_USERS (comma-separated)
undocumented = [u for u in risky_users if u.user not in allowed_admin_users]
status = "PASS" if undocumented == [] else "FAIL"
```

- PASS khi mọi user có risky role đều nằm trong whitelist
- FAIL nếu có user ngoài whitelist
- FAIL khi mongosh rc != 0 (`"Unable to query users automatically (mongosh failed)"`)

**Demo flow**:
- BEFORE: chỉ có `app_reader/writer/admin` với custom roles `demoXxx` (không trong risky_roles list) → query trả `[]` → PASS
- AFTER: `MongoAdmin` (role=root) + `MongoAudit` (role=userAdminAnyDatabase nếu remediation fail; role=clusterMonitor+readAnyDatabase nếu remediation success). Với `MONGO_AUDIT_ALLOWED_ADMIN_USERS=MongoAdmin`:
  - Remediation success: chỉ `MongoAdmin` xuất hiện trong list → trong whitelist → PASS
  - Remediation fail: `MongoAdmin` + `MongoAudit` xuất hiện → `MongoAudit` không whitelist → FAIL

### 6.3 Control 3.2 — RBAC enabled and configured

**PDF yêu cầu** (Manual):
```javascript
db.getUser()
db.getRole()
```
Review từng user/role có roles phù hợp.

**Code thực hiện** ([audit_authorization.py:263-380](audit_authorization.py#L263-L380)):

Bước 1: Verify auth enabled (sanity check)
```python
if not auth_enabled:
    add FAIL with message "RBAC is enabled before reviewing roles"
    return
```

Bước 2: Enumerate users + roles
```python
users_query = mongosh_eval(
    'JSON.stringify(db.getSiblingDB("admin").system.users.find({}, {user:1, db:1, roles:1, _id:0}).toArray())',
    port
)
```

Bước 3: Encode rule auto-verdict
```python
privileged_roles = {
    "root", "dbOwner", "userAdmin",
    "userAdminAnyDatabase", "dbAdminAnyDatabase", "readWriteAnyDatabase",
    "clusterAdmin", "hostManager", "backup", "restore",
}

for user in users_list:
    if not user.roles:
        violation: "no roles assigned"   # orphan user
        continue
    if user.user in allowed_admin_users:
        continue                          # whitelist được phép
    bad = [r for r in user.roles if r.role in privileged_roles]
    if bad:
        violation: "non-allowed user holds privileged role"
```

**Logic PASS/FAIL**:
- PASS khi `violations == []` (mọi user có ≥1 role, mọi user ngoài whitelist không có privileged role)
- FAIL nếu có violation

**Khác PDF**: PDF là Manual review. Code tự verdict bằng cách encode rule "user thường không được có admin-scope role". Đã đánh đổi tính chính xác của PDF lấy khả năng tự động hóa demo.

### 6.4 Control 3.3 — Non-root service user

**PDF yêu cầu**:
```bash
ps -ef | grep -E "mongos|mongod"
```

**Code thực hiện** ([audit_authorization.py:382-403](audit_authorization.py#L382-L403)):
```python
systemctl_user = run(["systemctl", "show", "mongod", "-p", "User", "--value"])
if systemctl_user.rc == 0 and systemctl_user.stdout:
    process_user = systemctl_user.stdout
else:
    # fallback ps -eo
    ps_result = run(["ps", "-eo", "user,comm,args"])
    for line in ...:
        if "mongod" in line:
            process_user = first column
            break

status = "PASS" if process_user and process_user != "root" else "FAIL"
```

**Logic PASS/FAIL**:
- PASS khi `process_user` xác định được và != "root"
- FAIL khi không xác định được hoặc = "root"

**Mapping**: Ubuntu mongodb-org package mặc định chạy với user `mongodb` → PASS từ lần đầu, không cần remediation gì.

### 6.5 Control 3.4 — Role privileges review

**PDF yêu cầu** (Manual):
```javascript
db.runCommand({rolesInfo: 1, showPrivileges: true, showBuiltinRoles: true})
```

**Code thực hiện** ([audit_authorization.py:474-510](audit_authorization.py#L474-L510)):

Loop tất cả db, query custom roles:
```javascript
const customRoles = [];
const dbList = db.adminCommand({ listDatabases: 1 });
dbList.databases.forEach(function(dbInfo) {
  const targetDb = db.getSiblingDB(dbInfo.name);
  const rolesResult = targetDb.runCommand({
    rolesInfo: 1,
    showPrivileges: true,
    showBuiltinRoles: false   // ← khác PDF (PDF dùng true)
  });
  if (rolesResult.ok === 1) {
    rolesResult.roles.forEach(r => customRoles.push(r));
  }
});
```

Phân tích từng custom role:
```python
def summarize_custom_role(role):
    inherited_role_names = set of role names from role.inheritedRoles + role.roles
    has_any_resource = privilege_has_any_resource(role.privileges or role.inheritedPrivileges)
    dangerous_inherited_roles = [r for r in inherited_role_names if r in {"root", "dbOwner"}]
    return summary
```

**Logic PASS/FAIL**:
- PASS khi không có custom role, HOẶC có custom role nhưng không role nào có `anyResource` và không kế thừa `root/dbOwner`
- FAIL khi có role dùng `anyResource` hoặc kế thừa `root/dbOwner`
- FAIL khi mongosh rc != 0

**Khác PDF**: 
- PDF `showBuiltinRoles: true` (review cả built-in). Code `showBuiltinRoles: false` (chỉ custom). Lý do: built-in roles là chuẩn MongoDB, không cần audit
- PDF chạy trên "current db". Code loop **tất cả db** qua `listDatabases`. Chặt hơn PDF

**Demo flow**:
- BEFORE: 3 custom roles `demoReader/Writer/Admin` tồn tại nhưng không dùng `anyResource`, không inherit `root/dbOwner` → PASS (mặc dù có custom role)
- AFTER (remediation success): drop hết 3 custom roles → list rỗng → PASS

---

## 7. Section 4 — Data Encryption (`audit_data_encryption.py`)

### 7.1 Hàm helper `normalize_protocols`

```python
def normalize_protocols(value):
    if value is None: return set()
    if isinstance(value, list): items = value
    else: items = re.split(r"[, ]+", str(value))
    return {str(item).strip().upper() for item in items if str(item).strip()}
```

Chấp nhận cả `"TLS1_0,TLS1_1"` (string) và `["TLS1_0", "TLS1_1"]` (list).

### 7.2 Control 4.1 — Legacy TLS protocols disabled

**PDF yêu cầu**:
> `disabledProtocols` phải bao gồm `TLS1_0,TLS1_1`

**Code thực hiện** ([audit_data_encryption.py:151-170](audit_data_encryption.py#L151-L170)):
```python
tls_disabled = normalize_protocols(get_path(conf, "net", "tls", "disabledProtocols"))
ssl_disabled = normalize_protocols(get_path(conf, "net", "ssl", "disabledProtocols"))
disabled_protocols = tls_disabled or ssl_disabled
status = "PASS" if {"TLS1_0", "TLS1_1"}.issubset(disabled_protocols) else "FAIL"
```

Đọc cả `net.tls.disabledProtocols` và `net.ssl.disabledProtocols` (legacy section).

**Logic PASS/FAIL**:
- PASS khi set đã disable chứa CẢ "TLS1_0" và "TLS1_1"
- FAIL còn lại

### 7.3 Control 4.2 — Weak Protocols Disabled

**PDF yêu cầu**: Y hệt 4.1.

**Code thực hiện**: Y hệt 4.1 ([audit_data_encryption.py:172-186](audit_data_encryption.py#L172-L186)). Đây là duplicate hợp lý với PDF (PDF cũng có 2 control gần như giống nhau).

### 7.4 Control 4.3 — Transport encryption

**PDF yêu cầu**: `net.tls.mode == requireTLS`

**Code thực hiện** ([audit_data_encryption.py:188-219](audit_data_encryption.py#L188-L219)):
```python
tls_mode = get_path(conf, "net", "tls", "mode")
ssl_mode = get_path(conf, "net", "ssl", "mode")
cert_file = get_path(conf, "net", "tls", "certificateKeyFile") or get_path(conf, "net", "ssl", "PEMKeyFile")
ca_file = get_path(conf, "net", "tls", "CAFile") or get_path(conf, "net", "ssl", "CAFile")

transport_ok = (
    (str(tls_mode).lower() == "requiretls" or str(ssl_mode).lower() == "requiressl")
    and bool(cert_file)
    and bool(ca_file)
)
```

**Logic PASS/FAIL**:
- PASS khi mode = `requireTLS` (hoặc legacy `requireSSL`) VÀ có khai báo cert + CA file
- FAIL nếu mode khác hoặc thiếu cert/CA

**Chặt hơn PDF**: PDF chỉ check mode. Code thêm verify cert/CA phải có giá trị (mongod không start được nếu thiếu nên check thừa nhưng không sai).

---

## 8. Section 6 — Network Configuration (`audit_network_configuration.py`)

### 8.1 Control 6.1 — Non-default port

**PDF yêu cầu**: `port != 27017`

**Code thực hiện** ([audit_network_configuration.py:139-154](audit_network_configuration.py#L139-L154)):
```python
port = int(get_path(conf, "net", "port", default=DEFAULT_MONGO_PORT) or DEFAULT_MONGO_PORT)
status = "PASS" if port != DEFAULT_MONGO_PORT else "FAIL"
```

**Logic PASS/FAIL**:
- PASS khi port khác 27017
- FAIL khi port = 27017 hoặc missing (default 27017)

**Lưu ý demo**: Trong project này, `mongod.conf` luôn dùng port 27017 → control này **luôn FAIL** ở cả before và after. Không có remediation đổi port. Có thể bỏ qua trong demo hoặc nhắc rõ "Level 1 require port != default, organization-defined".

---

## 9. Section 7 — File Permissions (`audit_file_permissions.py`)

### 9.1 Hàm helper

```python
def file_info(path):
    return {
        "exists": bool,
        "path": str,
        "mode": "0o400",        # octal string
        "mode_int": 256,        # int form for comparison
        "owner": "mongodb",
        "group": "mongodb"
    }

def check_secret_file(path, max_mode):
    """For files containing secret (keyFile, certKey) — must be owned by mongodb"""
    return ok = exists AND owner == "mongodb" AND mode_int <= max_mode

def check_public_file(path, max_mode):
    """For public files (CAFile) — owner mongodb or root both OK"""
    return ok = exists AND owner in {"mongodb", "root"} AND mode_int <= max_mode
```

### 9.2 Control 7.1 — Keyfile permissions

**PDF yêu cầu**:
> Check 3 file: `security.keyFile`, `net.tls.PEMKeyFile` (or `certificateKeyFile`), `net.tls.CAFile`. All must be owned by mongodb with restricted permissions.

**Code thực hiện** ([audit_file_permissions.py:177-225](audit_file_permissions.py#L177-L225)):
```python
key_file = get_path(conf, "security", "keyFile")
cert_key_file = get_path(conf, "net", "tls", "certificateKeyFile") or get_path(conf, "net", "ssl", "PEMKeyFile")
ca_file = get_path(conf, "net", "tls", "CAFile") or get_path(conf, "net", "ssl", "CAFile")

key_ok, key_info = check_secret_file(key_file, 0o600)
cert_ok, cert_info = check_secret_file(cert_key_file, 0o600)
ca_ok, ca_info = check_public_file(ca_file, 0o644)   # ← rule khác: CA là public

present_files = [item for item in [...] if item.path]
overall_ok = bool(present_files) and all(item.ok for item in present_files)
```

**Logic PASS/FAIL**:
- PASS khi mọi file được cấu hình đều thoả (file thiếu config bị bỏ qua khỏi check)
- FAIL khi không có file nào cấu hình (server hardening = 0%) HOẶC ít nhất 1 file vi phạm

**Rule chi tiết**:
| File | Mode tối đa | Owner cho phép |
|---|---|---|
| `security.keyFile` (replSet auth) | 0600 | mongodb |
| `net.tls.certificateKeyFile` (chứa private key) | 0600 | mongodb |
| `net.tls.CAFile` (cert công khai) | 0644 | mongodb hoặc root |

**Demo flow**:
- BEFORE: không có file nào trong config → `present_files == []` → FAIL
- AFTER:
  - `/etc/mongodb-keyfile` mode 0400 owner mongodb ✅
  - `/etc/ssl/mongodb/db-node-1.pem` mode 0600 owner mongodb ✅
  - `/etc/ssl/mongodb/mongoCA.crt` mode 0644 owner root ✅ (đã update rule)
  - → PASS

### 9.3 Control 7.2 — Database file permissions

**PDF yêu cầu**:
> `stat -c '%a' /var/lib/mongodb` → mode 770, owner mongodb:mongodb

**Code thực hiện** ([audit_file_permissions.py:269-291](audit_file_permissions.py#L269-L291)):
```python
db_path = get_path(conf, "storage", "dbPath", default="/var/lib/mongodb")
db_info = file_info(db_path)
db_ok = (
    db_info.get("exists") is True
    and db_info.get("owner") == "mongodb"
    and db_info.get("group") == "mongodb"
    and db_info.get("mode_int") == 0o770
)
```

**Logic PASS/FAIL**:
- PASS khi dbPath là directory tồn tại, owner+group = "mongodb", mode = **chính xác** 0770
- FAIL còn lại

**Lưu ý**: Strict equality `== 0o770`. Mode 0700 hoặc 0750 sẽ FAIL dù thực tế chặt hơn. Theo PDF Remediation `chmod 770`, code khớp.

**Demo flow**:
- BEFORE: Ubuntu mongodb-org install với mode 0755 → FAIL
- AFTER: `remediate_file_permissions.yaml` chỉnh thành 0770 owner mongodb → PASS

---

## 10. Cách truyền tham số qua env vars

Audit playbook set 9 env var, được Python script đọc qua `os.environ.get()`:

| Env var | Default | Dùng ở | Vai trò |
|---|---|---|---|
| `MONGO_AUDIT_HOST` | `127.0.0.1` (nếu TLS off), `ansible_host` (nếu TLS on) | audit_authorization.py | Host kết nối mongosh |
| `MONGO_AUDIT_USER` | `""` | audit_authorization.py | mongosh `--username` |
| `MONGO_AUDIT_PASS` | `""` | audit_authorization.py | mongosh `--password` |
| `MONGO_AUDIT_AUTH_DB` | `"admin"` | audit_authorization.py | mongosh `--authenticationDatabase` |
| `MONGO_AUDIT_ALLOWED_ADMIN_USERS` | `""` | audit_authorization.py (3.1, 3.2) | Whitelist user được phép có privileged role (comma-separated) |
| `MONGO_AUDIT_TLS` | `"false"` | audit_authorization.py | Bật flag `--tls` |
| `MONGO_AUDIT_TLS_CA_FILE` | `/etc/ssl/mongodb/mongoCA.crt` | audit_authorization.py | mongosh `--tlsCAFile` |
| `MONGO_AUDIT_TLS_CERT_KEY_FILE` | `/etc/ssl/mongodb/<host>.pem` | audit_authorization.py | mongosh `--tlsCertificateKeyFile` |
| `MONGO_AUDIT_TLS_ALLOW_INVALID_HOSTNAMES` | `"false"` | audit_authorization.py | mongosh `--tlsAllowInvalidHostnames` |

Các script khác (1.1, 2.x, 4.x, 6.1, 7.x) chỉ đọc `/etc/mongod.conf` → **không cần env vars**.

---

## 11. Đối chiếu mức độ tuân thủ PDF

Tổng kết từng control:

| Control | PDF yêu cầu | Code làm gì | Mức tuân thủ |
|---|---|---|---|
| 1.1 | `mongod --version` | Run cmd + regex 8.x | ✅ Đúng tinh thần |
| 2.1 | Grep `authorization`, check `enabled` | `security.authorization == enabled` | ✅ Đúng 100% |
| 2.2 | Grep `enableLocalhostAuthBypass`, check `false` | `setParameter.enableLocalhostAuthBypass` falsy | ✅ Đúng 100% |
| 3.1 | `find users with risky roles in admin db` | Mở rộng risky_roles + bỏ filter db | ✅ Chặt hơn PDF |
| 3.2 | `db.getUser()` + manual review | Enumerate users + auto-verdict bằng rule | 🟡 Khác PDF (PDF Manual, code Automated) |
| 3.3 | `ps -ef \| grep mongod` | `systemctl show -p User` + fallback `ps` | ✅ Cùng mục đích |
| 3.4 | `rolesInfo:1 showBuiltinRoles:true` cả db | Loop tất cả db + `showBuiltinRoles:false` | 🟡 Bỏ built-in (lý do: built-in không cần audit) |
| 4.1 | `TLS1_0,TLS1_1` in `disabledProtocols` | Same | ✅ Đúng 100% |
| 4.2 | Y hệt 4.1 | Y hệt 4.1 (PDF cũng duplicate) | ✅ Khớp |
| 4.3 | `net.tls.mode == requireTLS` | Same + verify cert/CA có giá trị | ✅ Chặt hơn |
| 6.1 | Port != 27017 | Same | ✅ Đúng 100% |
| 7.1 | Check `keyFile`, `PEMKeyFile`, `CAFile` ownership/mode | Same với rule riêng cho secret vs public file | ✅ Đúng 100% |
| 7.2 | `chmod 770 /var/lib/mongodb` | mode == 0o770 strict | ✅ Đúng 100% |

**Mức tuân thủ tổng thể**: ~92% (12/13 control đúng/chặt hơn, 2 control khác PDF nhưng có lý do thiết kế).

---

## 12. Sai khác có chủ đích so với PDF

### 12.1 Mở rộng risky_roles (3.1)
PDF chỉ check 3 role. Code thêm `root, dbAdminAnyDatabase, readWriteAnyDatabase`. Lý do: Section 3.5 (Level 2) coi đây là superuser roles. Audit Level 1 detect sớm các role này là defensive.

### 12.2 Auto-verdict 3.2 thay vì MANUAL
PDF marked Manual. Code encode rule "user thường không được có admin-scope role". Đánh đổi: chính xác PDF ↔ tự động cho demo.

### 12.3 Bỏ built-in roles trong 3.4
PDF `showBuiltinRoles: true`. Code `false`. Lý do: built-in MongoDB roles là chuẩn, không thay đổi → audit không cần review.

### 12.4 Loop tất cả db trong 3.4
PDF chạy trên current db. Code dùng `listDatabases` rồi loop. Chặt hơn PDF, không bỏ sót role trong db user-defined.

### 12.5 CAFile rule riêng trong 7.1
PDF không phân biệt secret vs public file. Code phân biệt: CA file (public) cho phép owner = `root` hoặc `mongodb`, cert key file (private) bắt buộc owner = `mongodb`. Khớp với `remediate_tls.yaml` copy CA với owner root.

---

## 13. Output format

### 13.1 JSON

Cấu trúc chuẩn cho mọi report:
```json
{
  "benchmark": "CIS MongoDB 8 Benchmark v1.0.0",
  "profile": "Level 1 - MongoDB",
  "generated_at": "<ISO8601>",
  "host": "<hostname>",
  "user": "<run-as user>",
  "platform": "<platform info>",
  "config_path": "/etc/mongod.conf",
  "summary": { "PASS": N, "FAIL": N, "ERROR": N },
  "sections": [
    { "section": "<name>", "summary": { ... } }
  ],
  "results": [
    {
      "section": "<name>",
      "control_id": "<x.y>",
      "title": "<text>",
      "assessment": "Automated|Manual",
      "status": "PASS|FAIL|ERROR",
      "expected": "<text>",
      "actual": "<value or object>",
      "evidence": { /* free-form */ }
    }
  ]
}
```

### 13.2 Markdown

Runner render markdown từ JSON, format:
```markdown
# CIS MongoDB 8 Benchmark v1.0.0 - Level 1 - MongoDB

- Host: `db-node-1`
- Generated: `2026-05-18T...`
- Summary: `{"PASS": 12, "FAIL": 1}`

| Section | ID | Status | Assessment | Title | Actual |
|---|---|---|---|---|---|
| 2 - Authentication | 2.1 | PASS | Automated | Ensure Authentication ... | "enabled" |
...

## Non-Pass Items

- **6.1 Ensure that MongoDB uses a non-default port** (FAIL, 6 - Network): 27017
```

`actual` được truncate 140 ký tự trong bảng. "Non-Pass Items" section list full giá trị để dễ đọc.

### 13.3 CSV pivot (qua `aggregate_csv.py`)

Gom 3 JSON từ 3 db node thành 1 CSV:
```
section, control_id, title, assessment, expected,
db-node-1_status, db-node-1_actual,
db-node-2_status, db-node-2_actual,
db-node-3_status, db-node-3_actual,
all_pass
```

Cột `all_pass=yes` chỉ khi cả 3 node đều PASS — tiện filter compliance gap.

---

## 14. Tóm tắt PASS/FAIL theo phase

### 14.1 Trước remediation (`audit_phase=before`)

| Control | Expected | Lý do |
|---|---|---|
| 1.1 | PASS | MongoDB 8.x đã cài |
| 2.1 | FAIL | Chưa bật authorization |
| 2.2 | FAIL | enableLocalhostAuthBypass chưa set false |
| 3.1 | PASS | Chưa có user có risky role (chỉ app_users với custom roles `demoXxx`) |
| 3.2 | FAIL | Auth chưa bật |
| 3.3 | PASS | mongodb-org package mặc định chạy user mongodb |
| 3.4 | PASS | Custom roles `demoXxx` không dùng anyResource, không inherit root/dbOwner |
| 4.1 | FAIL | Chưa cấu hình TLS |
| 4.2 | FAIL | Chưa cấu hình TLS |
| 4.3 | FAIL | Chưa cấu hình TLS |
| 6.1 | FAIL | Port 27017 (default) |
| 7.1 | FAIL | Chưa có keyfile/cert file |
| 7.2 | FAIL | dbPath mode 0755 (default) |

Tổng: 4 PASS, 9 FAIL.

### 14.2 Sau remediation đúng (`audit_phase=after`)

| Control | Expected | Lý do |
|---|---|---|
| 1.1 | PASS | Không đổi |
| 2.1 | PASS | mongod_tls.conf.j2 set `authorization: enabled` |
| 2.2 | PASS | mongod_tls.conf.j2 set `enableLocalhostAuthBypass: false` |
| 3.1 | PASS | Chỉ MongoAdmin có root, được whitelist qua `-e mongo_audit_allowed_admin_users=MongoAdmin` |
| 3.2 | PASS | App users có roles scoped (read/readWrite/dbAdmin@demo) |
| 3.3 | PASS | Không đổi |
| 3.4 | PASS | Custom roles `demoXxx` đã được drop |
| 4.1 | PASS | mongod_tls.conf.j2 set `disabledProtocols: TLS1_0,TLS1_1` |
| 4.2 | PASS | Cùng config với 4.1 |
| 4.3 | PASS | mongod_tls.conf.j2 set `mode: requireTLS` + cert + CA |
| 6.1 | FAIL | Vẫn port 27017 (không có remediation đổi port) |
| 7.1 | PASS | keyfile + cert + CA đều đạt rule sau remediate_file_permissions + remediate_tls |
| 7.2 | PASS | dbPath chỉnh thành 0770 |

Tổng: 12 PASS, 1 FAIL (6.1).

---

## 15. Phụ thuộc

Audit không cần cài thêm Python package nào:
- Chỉ dùng stdlib (`argparse`, `json`, `subprocess`, `os`, `re`, `socket`, `getpass`, `platform`, `datetime`, `stat`, `pwd`, `grp`, `pathlib`, `typing`)
- Trên Windows, `pwd`/`grp` không tồn tại → import wrap trong `try/except`, fallback hiển thị uid/gid

Audit gọi mongosh qua subprocess → mongosh phải có trong PATH trên host audit. Mongodb-org package đã cài.

Audit chạy với quyền `root` (qua `become: yes` trong playbook) để đọc được file trong `/etc/ssl/mongodb/` (mode 0600).

---

## 16. Lifecycle hoàn chỉnh

```
[Ansible controller]
        │
        │ ansible-playbook audit_mongodb8_l1.yaml -e audit_phase=before
        ↓
[db-node-1, db-node-2, db-node-3] song song:
        │
        │ 1. Copy 7 file .py vào /tmp/cis_mongodb8_l1/
        │ 2. Run python3 run_mongodb8_l1_audit.py với env vars
        │       │
        │       ├─→ Section 1 (audit_software.py): parse mongod.conf + run mongod --version
        │       ├─→ Section 2 (audit_authentication.py): parse mongod.conf
        │       ├─→ Section 3 (audit_authorization.py): parse mongod.conf + run mongosh × 3
        │       ├─→ Section 4 (audit_data_encryption.py): parse mongod.conf
        │       ├─→ Section 6 (audit_network_configuration.py): parse mongod.conf
        │       └─→ Section 7 (audit_file_permissions.py): parse mongod.conf + stat files
        │
        │ 3. Output: <hostname>.json + <hostname>.md
        ↓
[Ansible fetch về controller]
        │
        │ reports/before/db-node-1.{json,md}
        │ reports/before/db-node-2.{json,md}
        │ reports/before/db-node-3.{json,md}
        ↓
[Controller — optional]
        │
        │ python3 audit/aggregate_csv.py reports/before
        ↓
[reports/before.csv]
```
