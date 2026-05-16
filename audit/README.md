# CIS MongoDB 8 Level 1 Audit

This audit pack follows `CIS_MongoDB8_Benchmark_v1.0.0.pdf` and targets the
Level 1 MongoDB recommendations in the benchmark's seven sections.

## Files

- `audit/cis_mongodb8_l1_audit.py`: dependency-free Python runner for MongoDB nodes.
- `audit_mongodb8_l1.yaml`: Ansible wrapper that runs the audit and fetches reports.
- `reports/<phase>/`: generated JSON and Markdown reports.

## Run

```bash
ansible-playbook audit_mongodb8_l1.yaml -e audit_phase=before
```

After remediation:

```bash
ansible-playbook audit_mongodb8_l1.yaml -e audit_phase=after
```

If MongoDB authentication is already enabled, pass an audit account:

```bash
ansible-playbook audit_mongodb8_l1.yaml \
  -e audit_phase=after \
  -e mongo_audit_user=MongoAudit \
  -e mongo_audit_pass='ChangeMe'
```

## Level 1 Controls Covered

- `1.1` MongoDB version and patch level
- `2.1` Authentication enabled
- `2.2` Localhost authentication bypass disabled
- `3.1` Least privilege for database accounts
- `3.2` RBAC enabled and reviewed
- `3.3` MongoDB service runs as a non-root dedicated account
- `3.4` Role privileges reviewed
- `4.2` Weak TLS protocols disabled
- `4.3` Transport encryption required
- `5.1` System activity auditing configured
- `6.1` Non-default MongoDB port
- `7.1` Key file permissions
- `7.2` Database file permissions

Controls marked Manual in the benchmark are not forced into fake PASS values;
the runner collects evidence and marks them `MANUAL` when human review is still
required.
