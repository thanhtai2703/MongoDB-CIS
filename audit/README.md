# CIS MongoDB 8 Level 1 Audit

This audit pack follows `CIS_MongoDB8_Benchmark_v1.0.0.pdf` and targets the
Level 1 MongoDB recommendations in the benchmark's seven sections.

## Files

- `audit/run_mongodb8_l1_audit.py`: combined runner that calls the split section scripts.
- `playbooks/audit/audit_mongodb8_l1.yaml`: Ansible wrapper that runs the audit and fetches reports.
- `playbooks/audit/audit_sections.yaml`: runs the split section scripts and fetches one report per section.
- `audit/audit_software.py`: Section 1 runner.
- `audit/audit_authentication.py`: Section 2 runner.
- `audit/audit_authorization.py`: Section 3 runner.
- `audit/audit_data_encryption.py`: Section 4 runner.
- `audit/audit_system_activity.py`: Section 5 runner.
- `audit/audit_network_configuration.py`: Section 6 runner.
- `audit/audit_file_permissions.py`: Section 7 runner.
- `reports/<phase>/`: generated JSON and Markdown reports.

## Run

```bash
ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml -e audit_phase=before
```

To run the split section audits:

```bash
ansible-playbook playbooks/audit/audit_sections.yaml -e audit_phase=before
```

After remediation:

```bash
ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml -e audit_phase=after
```

Authentication/RBAC remediation for `2.1`, `2.2`, and `3.2`:

```bash
ansible-playbook playbooks/remediation/remediate_auth.yaml \
  -e mongo_admin_pass='AdminPass123!' \
  -e mongo_audit_pass='AuditPass123!'
```

File permission remediation for `7.1` and `7.2`:

```bash
ansible-playbook playbooks/remediation/remediate_file_permissions.yaml
```

TLS remediation for `4.2` and `4.3`:

```bash
ansible-playbook playbooks/remediation/remediate_tls.yaml
```

If MongoDB authentication is already enabled, pass an audit account:

```bash
ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml \
  -e audit_phase=after \
  -e mongo_audit_user=MongoAudit \
  -e mongo_audit_pass='AuditPass123!'
```

If TLS has also been enabled, pass TLS audit options:

```bash
ansible-playbook playbooks/audit/audit_mongodb8_l1.yaml \
  -e audit_phase=after \
  -e mongo_audit_user=MongoAudit \
  -e mongo_audit_pass='AuditPass123!' \
  -e mongo_audit_tls=true
```

## Level 1 Controls Covered

- `1.1` MongoDB version and patch level
- `2.1` Authentication enabled
- `2.2` Localhost authentication bypass disabled
- `2.3` Authentication enabled in cluster context
- `3.1` Least privilege for database accounts
- `3.2` RBAC enabled and reviewed
- `3.3` MongoDB service runs as a non-root dedicated account
- `3.4` Role privileges reviewed
- `4.1` Legacy TLS protocols disabled
- `4.2` Weak TLS protocols disabled
- `4.3` Transport encryption required
- `4.4` FIPS mode configured
- `4.5` Encryption at rest reviewed
- `5.1` System activity auditing configured
- `6.1` Non-default MongoDB port
- `7.1` Key file permissions
- `7.2` Database file permissions

Controls marked Manual in the benchmark are not forced into fake PASS values;
the runner collects evidence and marks them `MANUAL` when human review is still
required.
