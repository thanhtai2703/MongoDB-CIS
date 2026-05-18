# Tổng quan logic Remediation — mỗi playbook làm gì

Tài liệu mô tả 4 playbook remediation: chúng fix CIS control nào, thay đổi gì trên MongoDB, thứ tự task, và các phụ thuộc.

---

## 1. Cấu trúc tổng thể

### 1.1 4 playbook và thứ tự chạy

```
1. remediate_auth.yaml                  → Bật authentication + keyfile
2. remediate_authorization_roles.yaml   → Thu hẹp quyền user
3. remediate_file_permissions.yaml      → Sửa quyền file/folder
4. remediate_tls.yaml                   → Bật TLS encryption
```

**Thứ tự bắt buộc** vì có dependency:
- (2) cần `MongoAdmin` (do (1) tạo) để authenticate khi update users
- (3) cần keyfile path từ (1) để chỉnh quyền
- (4) cần keyfile (do (1) cài) — `mongod_tls.conf.j2` reference `keyFile`

### 1.2 Map CIS control → playbook

| CIS Control | Playbook chính | Hiệu ứng phụ |
|---|---|---|
| 2.1 Authorization enabled | `remediate_auth.yaml` | |
| 2.2 Localhost auth bypass | `remediate_auth.yaml` | |
| 3.1 Least privilege | `remediate_authorization_roles.yaml` | |
| 3.2 RBAC configured | `remediate_authorization_roles.yaml` | |
| 3.3 Non-root user | (đã sẵn từ package install) | |
| 3.4 Custom roles safe | `remediate_authorization_roles.yaml` | |
| 4.1 + 4.2 Legacy TLS disabled | `remediate_tls.yaml` | |
| 4.3 Transport encryption | `remediate_tls.yaml` | |
| 6.1 Non-default port | **(không có)** | |
| 7.1 Keyfile permissions | `remediate_auth.yaml` (tạo) + `remediate_file_permissions.yaml` (đảm bảo) | `remediate_tls.yaml` cũng đặt mode cho cert |
| 7.2 dbPath permissions | `remediate_file_permissions.yaml` | |

---

## 2. `remediate_auth.yaml` — Bật authentication

### 2.1 Mục tiêu
Chuyển MongoDB từ "ai cũng vào được" sang "phải đăng nhập".

### 2.2 Fix control nào
- **2.1** `security.authorization: enabled`
- **2.2** `setParameter.enableLocalhostAuthBypass: false`
- **3.3** (gián tiếp) keyfile cho replica set inter-node auth

### 2.3 Cấu trúc 3 play

**Play 1** — Cài keyfile trên cả 3 node:
- Generate random key 756 chars trên controller (`lookup('password')`)
- Copy cùng nội dung lên tất cả node ở `/etc/mongodb-keyfile` mode 0400 owner mongodb
- Lý do cùng nội dung: replica members dùng key này để authenticate lẫn nhau

**Play 2** — Tạo user trên primary (db-node-1):
- Đợi primary sẵn sàng (retry 12 lần × 5s) qua `db.hello().isWritablePrimary`
- Kết nối plain (chưa bật auth) qua `mongodb://10.148.0.2:27017/?directConnection=true&w=majority`
- Tạo 2 user qua `db.adminCommand`:
  - `MongoAdmin` — role `root@admin` (toàn quyền)
  - `MongoAudit` — role `clusterMonitor + userAdminAnyDatabase + readAnyDatabase` (sẽ bị thu hẹp ở playbook tiếp)

**Play 3** — Bật authorization:
- Render template `mongod_auth.conf.j2` đè lên `/etc/mongod.conf` (thêm `security.authorization=enabled` + `keyFile` path + `enableLocalhostAuthBypass=false`)
- Restart mongod
- `wait_for port 27017` đợi mongod sống lại

### 2.4 Gotcha
- **Sau play 3, replica set cần ~10-30s để bầu primary mới**. Playbook tiếp theo phải đợi primary writable.
- **Idempotency**: rerun sau khi auth đã bật sẽ fail vì seed URI không có credentials → mongosh không kết nối được.
- **Sequence quan trọng**: cài keyfile trước tạo user. Nếu ngược lại, mongod không khởi động được vì keyfile thiếu.

---

## 3. `remediate_authorization_roles.yaml` — Thu hẹp quyền

### 3.1 Mục tiêu
Áp dụng nguyên tắc least privilege: mỗi user chỉ có role tối thiểu cần thiết.

### 3.2 Fix control nào
- **3.1** Cắt `userAdminAnyDatabase` khỏi MongoAudit (chỉ giữ clusterMonitor + readAnyDatabase)
- **3.2** App users (`app_reader/writer/admin`) chuyển từ custom role `demoXxx@admin` (full scope) sang built-in scoped roles (`read/readWrite/dbAdmin @ demo`)
- **3.4** Drop 3 custom role `demoReader/Writer/Admin` không còn dùng

### 3.3 Cấu trúc task

**Task 1** — Auto-detect TLS:
```bash
grep -qE '^[[:space:]]*mode:[[:space:]]*requireTLS' /etc/mongod.conf && echo true || echo false
```
→ Đọc mongod.conf để biết hiện tại đã bật TLS chưa. Quyết định cách connect mongosh.

**Task 2** — Build connection args:
- Nếu TLS off: `--host 127.0.0.1`
- Nếu TLS on: `--host <ansible_host> --tls --tlsCAFile ... --tlsCertificateKeyFile ... --tlsAllowInvalidHostnames`

**Task 3** — Wait until writable primary:
```bash
mongosh ... --eval "db.hello().isWritablePrimary" | tail -n1
```
Retry tối đa 24 lần × 5s = 2 phút. Lý do: tránh race condition khi remediate_auth vừa restart mongod xong.

**Task 4** — Reduce MongoAudit:
```javascript
adb.updateUser("MongoAudit", {
  roles: [
    { role: "clusterMonitor", db: "admin" },
    { role: "readAnyDatabase", db: "admin" }
  ]
});
```

**Task 5** — Replace app user roles + drop custom roles:
```javascript
updateIfExists("app_reader", [{role: "read", db: "demo"}]);
updateIfExists("app_writer", [{role: "readWrite", db: "demo"}]);
updateIfExists("app_admin",  [{role: "readWrite", db: "demo"}, {role: "dbAdmin", db: "demo"}]);

["demoReader","demoWriter","demoAdmin"].forEach(r => adb.dropRole(r));
```

### 3.4 Gotcha
- **Wait-for-primary là bắt buộc**: thiếu task này, playbook fail silently khi primary chưa elected — đã gặp trong demo trước.
- **`no_log: true` ẩn lỗi**: đã đổi thành `no_log: false` để debug dễ hơn.
- **`updateIfExists` skip silent**: nếu user (vd. `app_writer`) chưa tồn tại do bỏ qua `seed_data.yaml`, task không làm gì cũng không cảnh báo.

---

## 4. `remediate_file_permissions.yaml` — Quyền file

### 4.1 Mục tiêu
Đảm bảo các file/folder sensitive của MongoDB không bị user khác đọc được.

### 4.2 Fix control nào
- **7.1** Keyfile `/etc/mongodb-keyfile` mode 0400 owner mongodb (idempotent với play 1 của remediate_auth)
- **7.2** dbPath `/var/lib/mongodb` mode 0770 owner mongodb:mongodb

### 4.3 Cấu trúc task

**Task 1** — Strict keyfile permissions:
```yaml
file:
  path: /etc/mongodb-keyfile
  owner: mongodb
  mode: "0400"
```

**Task 2** — Set dbPath directory:
```yaml
file:
  path: /var/lib/mongodb
  state: directory
  owner: mongodb
  group: mongodb
  mode: "0770"
```

**Task 3** — Recursive chown:
```yaml
file:
  path: /var/lib/mongodb
  owner: mongodb
  group: mongodb
  recurse: yes
```
Đảm bảo mọi file trong dbPath cũng thuộc user mongodb (đôi khi root tạo file khi mongod restart).

**Task 4** — Restore directory mode sau recurse:
```yaml
file:
  path: /var/lib/mongodb
  state: directory
  mode: "0770"
```
Vì recurse có thể đụng mode của directory.

**Task 5** — Restart mongod + wait_for port.

### 4.4 Gotcha
- **Restart mongod vô điều kiện**: kể cả khi không có file nào thay đổi, mongod vẫn restart. Mỗi lần restart tốn 10-30s đợi primary election. Có thể chuyển sang notify/handler để tối ưu.
- **`recurse: yes` không set mode**: chỉ chown, không chmod. Đúng (an toàn) — chmod recurse trên dbPath có thể phá WiredTiger file mode.

---

## 5. `remediate_tls.yaml` — Bật mã hóa transport

### 5.1 Mục tiêu
Mã hóa toàn bộ traffic vào MongoDB (mongod ↔ mongod, client ↔ mongod).

### 5.2 Fix control nào
- **4.1 + 4.2** `disabledProtocols: TLS1_0,TLS1_1`
- **4.3** `mode: requireTLS` + cert + CA
- **7.1** (bổ sung) cert file mode 0600 owner mongodb, CA mode 0644 owner root

### 5.3 Cấu trúc 4 giai đoạn

**Giai đoạn A — Generate CA trên controller (delegate_to: localhost)**:
1. Tạo thư mục `/tmp/automation_cis_mongodb_tls_$USER/`
2. Generate CA private key (4096 bit RSA)
3. Self-sign CA certificate (CN="Automation-CIS MongoDB CA", 10 năm)

**Giai đoạn B — Per-node cert generation (delegate_to: localhost, loop database_nodes)**:
1. Render OpenSSL config với SAN gồm `DNS=<hostname>`, `IP=<ansible_host>`, `IP=127.0.0.1`
2. Generate node private key
3. Generate CSR
4. Sign CSR bằng CA (825 ngày)
5. Concatenate key + cert thành PEM file

**Giai đoạn C — Verify artifacts**:
- Stat CA + PEM trên controller, fail nếu thiếu

**Giai đoạn D — Install + apply (chạy trên mỗi node)**:
1. Tạo thư mục `/etc/ssl/mongodb/` mode 0755 owner mongodb
2. Copy CA cert → `/etc/ssl/mongodb/mongoCA.crt` mode 0644 owner root
3. Copy node PEM → `/etc/ssl/mongodb/<hostname>.pem` mode 0600 owner mongodb
4. Render `mongod_tls.conf.j2` (auth + keyfile + TLS) đè lên `/etc/mongod.conf`
5. Restart mongod + wait_for port

### 5.4 Cấu trúc cert SAN

Mỗi node có cert riêng với SAN:
```
CN = db-node-1
DNS.1 = db-node-1
IP.1 = 10.148.0.2     (ansible_host)
IP.2 = 127.0.0.1      (cho localhost connect)
```

Cả 3 cert đều sign bởi cùng 1 CA → trust chain hoạt động khi mongod connect lẫn nhau.

### 5.5 Gotcha
- **`creates:` flag khắp nơi**: OpenSSL command có `creates:` để skip nếu file đã tồn tại. Khi rebuild infra với IP mới, **cert config không regenerate** → SAN sai → handshake fail.
  - Workaround: xoá `/tmp/automation_cis_mongodb_tls_*/` trước khi rebuild
- **Dependency ngầm vào remediate_auth**: `mongod_tls.conf.j2` reference `keyFile` path. Chạy tls trước auth → mongod fail start.
- **`allowConnectionsWithoutCertificates: true`**: client không bắt buộc có cert (chỉ cần server có). Trade-off để PHP/web client không phải có cert riêng. Production strict hơn sẽ set `false` + cấp client cert.
- **`tlsAllowInvalidHostnames` ở client**: skip hostname/SAN check. Vẫn verify CA chain. Dùng vì replica set discovery có thể connect bằng IP/hostname khác cert SAN.

---

## 6. Phụ thuộc + race condition

### 6.1 Sơ đồ phụ thuộc

```
remediate_auth.yaml
        │ (tạo /etc/mongodb-keyfile, MongoAdmin, MongoAudit)
        │ (render mongod_auth.conf.j2 → restart mongod)
        │
        │ ⏳ Đợi primary election (5-30s)
        ↓
remediate_authorization_roles.yaml
        │ (cần MongoAdmin để authenticate)
        │ (cần primary writable để updateUser)
        │ ✓ Có wait-for-primary built-in
        ↓
remediate_file_permissions.yaml
        │ (chỉnh mode keyfile + dbPath)
        │ (restart mongod)
        │
        │ ⏳ Đợi primary election
        ↓
remediate_tls.yaml
        │ (cần keyfile tồn tại, mongod_tls.conf.j2 reference)
        │ (render mongod_tls.conf.j2 → restart mongod với TLS)
```

### 6.2 Race condition đã xử lý

| Bước | Vấn đề | Cách fix |
|---|---|---|
| Sau remediate_auth | Primary chưa elected | `wait_for_primary` ở đầu remediate_authorization_roles |
| Sau remediate_file_permissions | Primary chưa elected | (chưa fix — risk thấp vì remediate_tls không cần writable primary) |
| Khi remediate_authorization_roles connect | Không biết TLS đã bật chưa | `auto-detect` từ mongod.conf |

### 6.3 Race condition CHƯA xử lý

- **Rebuild scenario**: `/tmp/automation_cis_mongodb_tls_*/` còn cert cũ → cert mới không regenerate. **Workaround**: `rm -rf /tmp/automation_cis_mongodb_tls_*` trước khi rebuild infra.
- **remediate_tls không có wait-for-primary**: nhưng task này chỉ render config + restart, không update DB, nên không cần.

---

## 7. State changes — trước vs sau từng playbook

### 7.1 Trạng thái MongoDB qua từng bước

| Bước | mongod.conf | Users | Custom roles | File perms |
|---|---|---|---|---|
| Sau setup_mongodb | plain (no auth, no tls) | — | — | dbPath 0755 |
| Sau seed_data | plain | app_reader/writer/admin | demoReader/Writer/Admin | dbPath 0755 |
| Sau **remediate_auth** | + authorization=enabled + keyFile + localhostBypass=false | + MongoAdmin, MongoAudit | (giữ nguyên) | + /etc/mongodb-keyfile 0400 |
| Sau **remediate_authorization_roles** | (không đổi) | MongoAudit thu hẹp, app_* đổi role | drop demoXxx | (không đổi) |
| Sau **remediate_file_permissions** | (không đổi) | (không đổi) | (không đổi) | dbPath 0770 |
| Sau **remediate_tls** | + tls.mode=requireTLS + cert + CA + disabledProtocols | (không đổi) | (không đổi) | + cert 0600, CA 0644 |

### 7.2 Trạng thái web

| Bước | Web URI gì | Connect được? |
|---|---|---|
| Sau setup_mongodb + web (lần 1) | plain TCP, no creds | ✅ (auth off) |
| Sau remediate_auth (chưa rerun web) | (web vẫn dùng plain TCP) | ❌ (auth required) |
| Sau remediate_tls (chưa rerun web) | (plain TCP) | ❌ (requireTLS) |
| Sau **rerun web với -e mongodb_app_tls=true** | TLS + app_writer | ✅ |

---

## 8. Idempotency check

| Playbook | Rerun an toàn? | Lý do |
|---|---|---|
| `remediate_auth.yaml` | ⚠ KHÔNG | Seed URI không có creds → rerun sau auth bật sẽ fail |
| `remediate_authorization_roles.yaml` | ✅ Có | `updateIfExists` skip nếu user không có; `dropRole` có try/catch |
| `remediate_file_permissions.yaml` | ✅ Có | File module idempotent + restart mongod vô điều kiện |
| `remediate_tls.yaml` | ⚠ Phần lớn có | `creates:` flag skip OpenSSL command. Nhưng nếu IP đổi mà CA giữ → cert SAN không match |

---

## 9. Tóm tắt — Khi nào dùng playbook nào

| Tình huống | Playbook |
|---|---|
| Lần đầu setup từ vulnerable → hardened | Chạy tuần tự cả 4 playbook |
| Xoay password MongoAdmin | Edit creds trong vars, chạy `remediate_auth.yaml` (cẩn thận, không idempotent) |
| Thêm/bớt user app | Edit `remediate_authorization_roles.yaml`, rerun |
| Tăng strictness mode TLS | Edit `templates/mongod_tls.conf.j2` (bật `allowConnectionsWithoutCertificates: false`), rerun `remediate_tls.yaml` |
| Mỗi node cần TLS cert mới (đổi IP) | Xoá `/tmp/automation_cis_mongodb_tls_$USER/<host>.{key,csr,crt,pem,cnf}` rồi rerun `remediate_tls.yaml` |
| Reset toàn cluster về plain | (Không có playbook reset — cách nhanh: `terraform destroy && apply`) |

---

## 10. Các điểm yếu cần lưu ý cho production

1. **Password hardcoded trong vars**: defaults như `AdminPass123!` không an toàn. Production dùng `ansible-vault` hoặc external secret store.
2. **CA private key trên controller `/tmp/`**: nếu controller bị compromise, attacker có thể giả mạo cert. Production nên dùng HSM hoặc Vault PKI.
3. **`tlsAllowInvalidHostnames=true`** ở client: bypass hostname verification. Production nên fix DNS để cert SAN khớp.
4. **`allowConnectionsWithoutCertificates=true`**: cho phép client không cần cert. Production strict nên dùng mutual TLS (mTLS).
5. **Không có rotation cho keyfile và cert**: production cần playbook xoay key/cert định kỳ.
6. **Port 27017 mặc định**: project không đổi → CIS 6.1 luôn FAIL. Production set `net.port` khác.
