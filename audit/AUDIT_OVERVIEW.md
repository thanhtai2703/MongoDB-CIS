# Tổng quan logic Audit — mỗi control kiểm gì

Tài liệu mô tả ngắn gọn từng control làm gì, dành cho thuyết trình/giải thích người không đọc code. Mỗi control gồm 3 phần: **kiểm gì**, **làm thế nào**, **PASS khi nào**.

Xem chi tiết kỹ thuật ở [AUDIT_LOGIC.md](AUDIT_LOGIC.md).

---

## Section 1 — Software

### 1.1 Phiên bản MongoDB
- **Kiểm gì**: Server đang chạy đúng MongoDB version được tổ chức phê duyệt không.
- **Làm thế nào**: Chạy `mongod --version` rồi đọc chuỗi version.
- **PASS khi**: Version bắt đầu bằng "8." (ví dụ 8.0.5).

---

## Section 2 — Authentication

### 2.1 Authentication đã bật chưa
- **Kiểm gì**: MongoDB có bắt buộc client phải đăng nhập trước khi truy cập không.
- **Làm thế nào**: Đọc `mongod.conf`, tìm khóa `security.authorization`.
- **PASS khi**: Giá trị = `enabled`.

### 2.2 Tắt localhost auth bypass
- **Kiểm gì**: Có ai từ localhost truy cập mà không cần đăng nhập không.
- **Làm thế nào**: Đọc `mongod.conf`, tìm khóa `setParameter.enableLocalhostAuthBypass`.
- **PASS khi**: Giá trị = `false` (mặc định MongoDB là `true` → cần explicit tắt mới đạt).

---

## Section 3 — Authorization

### 3.1 Quyền tối thiểu cho tài khoản
- **Kiểm gì**: Có user nào đang giữ role mạnh (như `root`, `userAdminAnyDatabase`, `readWriteAnyDatabase`,...) mà không nằm trong danh sách admin được phép không.
- **Làm thế nào**: Kết nối mongosh, query `admin.system.users` tìm user có 1 trong các role nguy hiểm. So sánh với whitelist truyền qua env `MONGO_AUDIT_ALLOWED_ADMIN_USERS`.
- **PASS khi**: Mọi user có role mạnh đều nằm trong whitelist (hoặc không có user nào có role mạnh).

### 3.2 RBAC được cấu hình đúng
- **Kiểm gì**: Mỗi user có được gán role phù hợp với chức năng không. Có user nào không có role nào (orphan) hoặc user thường (không phải admin) lại có role admin không.
- **Làm thế nào**: Enumerate toàn bộ user qua mongosh, kiểm tra:
  - User không trong whitelist → không được giữ role privileged
  - Mọi user phải có ≥1 role
- **PASS khi**: Tất cả user có role + user thường không có role admin.

### 3.3 MongoDB không chạy bằng root
- **Kiểm gì**: Process mongod được chạy bằng user nào (không được là root).
- **Làm thế nào**: Đọc `systemctl show mongod -p User` (fallback `ps -eo user`).
- **PASS khi**: User chạy process != "root" (Ubuntu mongodb-org mặc định chạy user `mongodb`).

### 3.4 Custom role có an toàn không
- **Kiểm gì**: Các role tự định nghĩa (do admin tạo) có dùng quyền siêu rộng (`anyResource`) hoặc kế thừa role nguy hiểm (`root`, `dbOwner`) không.
- **Làm thế nào**: Loop tất cả database trong cluster, query `rolesInfo` để lấy custom roles + privileges. Scan từng role tìm `anyResource` và `inheritedRoles` có chứa `root/dbOwner` không.
- **PASS khi**: Không custom role nào nguy hiểm (hoặc không có custom role nào).

---

## Section 4 — Data Encryption

### 4.1 Tắt TLS legacy protocols
- **Kiểm gì**: Server có cấm các phiên bản TLS yếu (TLS 1.0, 1.1) không.
- **Làm thế nào**: Đọc `mongod.conf`, lấy `net.tls.disabledProtocols`.
- **PASS khi**: Cả `TLS1_0` và `TLS1_1` đều có trong danh sách disabled.

### 4.2 Tắt weak protocols
- **Kiểm gì**: Giống 4.1 (PDF benchmark có 2 control gần như giống nhau).
- **Làm thế nào**: Cùng logic với 4.1.
- **PASS khi**: Cùng điều kiện với 4.1.

### 4.3 Mã hóa data in transit (TLS)
- **Kiểm gì**: Mọi kết nối tới MongoDB có bị bắt buộc phải dùng TLS không.
- **Làm thế nào**: Đọc `mongod.conf`, kiểm 3 thứ: `net.tls.mode = requireTLS`, `certificateKeyFile` có giá trị, `CAFile` có giá trị.
- **PASS khi**: Cả 3 điều kiện trên đều thoả.

---

## Section 6 — Network

### 6.1 Port không phải mặc định
- **Kiểm gì**: MongoDB có dùng port khác 27017 (port mặc định, dễ bị scan) không.
- **Làm thế nào**: Đọc `mongod.conf`, lấy `net.port`.
- **PASS khi**: Port != 27017.

> **Lưu ý**: Project hiện không có remediation đổi port → control này luôn FAIL.

---

## Section 7 — File Permissions

### 7.1 Quyền file chứa secret
- **Kiểm gì**: 3 file nhạy cảm trên disk có bị set quyền lỏng cho user khác đọc không.
- **Làm thế nào**: Đọc đường dẫn từ `mongod.conf` rồi `stat` từng file:
  - `security.keyFile` — file chia sẻ giữa các replica member để authenticate
  - `net.tls.certificateKeyFile` — chứa private key TLS của node
  - `net.tls.CAFile` — chứng chỉ CA công khai
- **PASS khi**:
  - keyFile & certKey: owner=mongodb, mode ≤ 0600 (chỉ owner đọc)
  - CAFile: owner=mongodb hoặc root, mode ≤ 0644 (public cert)

### 7.2 Quyền thư mục database
- **Kiểm gì**: Thư mục chứa data MongoDB (`/var/lib/mongodb`) có bị user khác truy cập được không.
- **Làm thế nào**: Đọc `storage.dbPath` từ config, `stat` directory.
- **PASS khi**: Owner=mongodb, group=mongodb, mode chính xác = 0770 (chỉ owner và group đọc/ghi).

---

## Tóm tắt bằng 1 câu mỗi control

| ID | Một câu |
|---|---|
| **1.1** | MongoDB version đúng major version yêu cầu (8.x) |
| **2.1** | MongoDB bắt buộc client đăng nhập |
| **2.2** | Localhost không được bỏ qua đăng nhập |
| **3.1** | User có quyền cao đều được liệt kê chính thức |
| **3.2** | Mỗi user có role phù hợp, không có user thường giữ role admin |
| **3.3** | MongoDB không chạy bằng root |
| **3.4** | Custom role không dùng quyền siêu rộng |
| **4.1** | TLS 1.0 và 1.1 bị cấm |
| **4.2** | Tương tự 4.1 |
| **4.3** | Mọi kết nối phải qua TLS |
| **6.1** | Port khác 27017 mặc định |
| **7.1** | File key/cert chỉ mongodb đọc được |
| **7.2** | Thư mục data chỉ mongodb truy cập |

---

## Kết quả demo theo từng phase

### Trước remediation (state vulnerable)
```
PASS:  1.1, 3.1*, 3.3, 3.4
FAIL:  2.1, 2.2, 3.2, 4.1, 4.2, 4.3, 6.1, 7.1, 7.2
```
*3.1 PASS "giả" vì chưa có user nào có role nguy hiểm (mới chỉ có `app_*` với custom role `demoXxx`).

### Sau remediation đúng (state hardened)
```
PASS:  1.1, 2.1, 2.2, 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 7.1, 7.2
FAIL:  6.1 (không có remediation đổi port)
```

→ **Cải thiện 9 → 12 PASS** (chỉ còn 1 FAIL hợp lý ở 6.1).

---

## Khi nào audit không cho kết quả tin cậy

| Trường hợp | Kết quả | Xử lý |
|---|---|---|
| mongosh không kết nối được DB | 3.1, 3.2, 3.4 → FAIL với `actual = "Unable to query..."` | Check creds, TLS flags |
| File `mongod.conf` không tồn tại | Mọi section parse-config → FAIL với `evidence.config_error` set | Verify mongod đã cài chưa |
| Cert file đường dẫn sai trong config | 7.1 → FAIL với `info.exists = false` | Check `remediate_tls.yaml` đã chạy chưa |
| Script Python crash | Section đó → status `ERROR` (do runner wrap) | Đọc evidence.stderr |
