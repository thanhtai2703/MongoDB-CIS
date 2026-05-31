# Makefile cho Automation CIS MongoDB demo
# Tự động hoá: Terraform → SSH control-node → Ansible playbook → fetch report
# Yêu cầu: terraform, ssh, scp, python3, make

SSH_KEY     := gcp-key.pem
SSH_USER    := ubuntu
SSH_OPTS    := -i $(SSH_KEY) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
PROJECT_DIR := MongoDB-CIS

CONTROL_IP   = $(shell cd terraform && terraform output -raw control_external_ip 2>/dev/null)
SSH          = ssh $(SSH_OPTS) $(SSH_USER)@$(CONTROL_IP)
SCP          = scp $(SSH_OPTS) -r

ADMIN_PASS  := AdminPass123!
AUDIT_PASS  := AuditPass123!
APP_PASS    := WriterPass123!

# =========================================================
# Help
# =========================================================
.PHONY: help
help:
	@echo "Demo flow chia 3 giai đoạn:"
	@echo ""
	@echo "  GIAI ĐOẠN 1 — Hạ tầng + MongoDB"
	@echo "    make setup            Terraform apply + sync code + cài Mongo + seed + web"
	@echo ""
	@echo "  GIAI ĐOẠN 2 — Audit"
	@echo "    make audit-before     Audit phase=before (state vulnerable)"
	@echo "    make audit-after      Audit phase=after (state hardened)"
	@echo ""
	@echo "  GIAI ĐOẠN 3 — Remediation"
	@echo "    make remediate        Chạy 5 playbook + redeploy web "
	@echo "    make web-cert         Sinh client cert + deploy"
	@echo ""
	@echo "  TIỆN ÍCH"
	@echo "    make report-before    Gom CSV chỉ phase=before"
	@echo "    make report-after     Gom CSV chỉ phase=after"
	@echo "    make report           Gom cả 2 CSV (= report-before + report-after)"
	@echo "    make demo             Full pipeline: setup → audit-before → remediate → audit-after → report"
	@echo "    make ssh              SSH vào control-node"
	@echo "    make clean            Terraform destroy"
	@echo ""
	@echo "  Control IP hiện tại: $(CONTROL_IP)"

# =========================================================
# GIAI ĐOẠN 1 — Hạ tầng + MongoDB
# =========================================================
.PHONY: infra wait-ready sync setup

infra:
	@echo "→ Terraform apply..."
	cd terraform && terraform init -upgrade && terraform apply -auto-approve
	@echo ""
	@echo "✓ Hạ tầng sẵn sàng. Control IP: $$(cd terraform && terraform output -raw control_external_ip)"

wait-ready:
	@echo "→ Đợi cloud-init trên control-node hoàn tất..."
	@until $(SSH) "[ -f /tmp/startup-done ]" 2>/dev/null; do sleep 5; printf "."; done
	@echo " ✓ ready"

sync: wait-ready
	@echo "→ Sync code lên control-node..."
	@$(SSH) "mkdir -p ~/$(PROJECT_DIR)"
	$(SCP) playbooks audit templates group_vars inventory.yaml ansible.cfg $(SSH_KEY) \
	  $(SSH_USER)@$(CONTROL_IP):~/$(PROJECT_DIR)/
	@$(SSH) "chmod 600 ~/$(PROJECT_DIR)/$(SSH_KEY)"
	@echo "✓ Sync xong"

setup: infra sync
	@echo "→ Cài MongoDB + seed data + deploy web (state vulnerable)..."
	$(SSH) "cd ~/$(PROJECT_DIR) && \
	  ansible-playbook playbooks/core/prepare.yaml && \
	  ansible-playbook playbooks/core/setup_mongodb.yaml && \
	  ansible-playbook playbooks/core/seed_data.yaml && \
	  ansible-playbook playbooks/core/web.yaml"
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  ✓ GIAI ĐOẠN 1 HOÀN TẤT"
	@echo "  → Mở web: http://$$(cd terraform && terraform output -raw web_lb_ip)"
	@echo "═══════════════════════════════════════════════"

# =========================================================
# GIAI ĐOẠN 2 — Audit
# =========================================================
.PHONY: audit-before audit-after

audit-before: sync
	@echo "→ Audit phase=before..."
	$(SSH) "cd ~/$(PROJECT_DIR) && ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml -e audit_phase=before"
	@mkdir -p reports/before
	@echo "→ Fetch report về local..."
	$(SCP) $(SSH_USER)@$(CONTROL_IP):~/$(PROJECT_DIR)/reports/before/. reports/before/
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  ✓ AUDIT BEFORE HOÀN TẤT"
	@echo "  → Report: reports/before/*.{json,md}"
	@echo "═══════════════════════════════════════════════"

audit-after: sync
	@echo "→ Audit phase=after..."
	$(SSH) "cd ~/$(PROJECT_DIR) && ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml \
	  -e audit_phase=after \
	  -e mongo_audit_user=MongoAdmin \
	  -e mongo_audit_pass='$(ADMIN_PASS)' \
	  -e mongo_audit_allowed_admin_users=MongoAdmin \
	  -e mongo_audit_tls=true \
	  -e mongo_audit_tls_allow_invalid_hostnames=true"
	@mkdir -p reports/after
	@echo "→ Fetch report về local..."
	$(SCP) $(SSH_USER)@$(CONTROL_IP):~/$(PROJECT_DIR)/reports/after/. reports/after/
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  ✓ AUDIT AFTER HOÀN TẤT"
	@echo "  → Report: reports/after/*.{json,md}"
	@echo "═══════════════════════════════════════════════"

# =========================================================
# GIAI ĐOẠN 3 — Remediation
# =========================================================
.PHONY: remediate web-cert

remediate: sync
	@echo "→ Chạy 5 playbook remediation theo thứ tự + rerun web (chưa có client cert → web sẽ FAIL kết nối)..."
	$(SSH) "cd ~/$(PROJECT_DIR) && \
	  ansible-playbook playbooks/remediation/remediation_update_mongodb_port.yaml && \
	  ansible-playbook playbooks/remediation/remediate_auth.yaml \
	    -e mongo_admin_pass='$(ADMIN_PASS)' && \
	  ansible-playbook playbooks/remediation/remediate_authorization_roles.yaml \
	    -e mongo_admin_pass='$(ADMIN_PASS)' && \
	  ansible-playbook playbooks/remediation/remediate_file_permissions.yaml && \
	  ansible-playbook playbooks/remediation/remediate_tls.yaml && \
	  ansible-playbook playbooks/core/web.yaml \
	    -e mongodb_app_user=app_writer -e mongodb_app_pass='$(APP_PASS)' -e mongodb_app_tls=true"
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  ✓ GIAI ĐOẠN 3 HOÀN TẤT"
	@echo "  → MongoDB: port=27018, requireTLS + mutual TLS"
	@echo "  ⚠ Web SẼ FAIL kết nối vì chưa có client cert (strict CIS)"
	@echo "  → Chạy 'make web-cert' để sinh client cert + restore web"
	@echo "═══════════════════════════════════════════════"

web-cert: sync
	@echo "→ Sinh client cert cho web (signed by MongoDB CA) + deploy + restart php-fpm..."
	$(SSH) "cd ~/$(PROJECT_DIR) && \
	  ansible-playbook playbooks/remediation/issue_web_client_cert.yaml"
	@echo ""
	@echo "═══════════════════════════════════════════════"
	@echo "  ✓ WEB CLIENT CERT ĐÃ CẤP"
	@echo "  → Web giờ kết nối được qua mutual TLS"
	@echo "═══════════════════════════════════════════════"

# =========================================================
# Tiện ích
# =========================================================
.PHONY: report report-before report-after demo ssh clean

report-before:
	@echo "→ Gom CSV phase=before..."
	@python audit/aggregate_csv.py reports/before
	@echo "✓ CSV: reports/before.csv"

report-after:
	@echo "→ Gom CSV phase=after..."
	@python audit/aggregate_csv.py reports/after
	@echo "✓ CSV: reports/after.csv"

report: report-before report-after
	@echo "✓ CSV before + after đã sẵn sàng"

demo: setup audit-before remediate web-cert audit-after report
	@echo ""
	@echo "════════════════════════════════════════════════════"
	@echo "  ✓ DEMO FLOW HOÀN TẤT"
	@echo "  → Web URL: http://$$(cd terraform && terraform output -raw web_lb_ip)"
	@echo "  → Reports: reports/before.csv, reports/after.csv"
	@echo "════════════════════════════════════════════════════"

ssh:
	@$(SSH)

clean:
	@echo "→ Terraform destroy..."
	cd terraform && terraform destroy -auto-approve
	@echo "→ Cleanup local CA cache..."
	@rm -rf /tmp/automation_cis_mongodb_tls_* 2>/dev/null || true
	@echo "✓ Cleaned"
