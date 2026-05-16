# Terraform - GCP infrastructure for Automation_CIS

This stack provisions the lab infrastructure used for the MongoDB CIS demo:

- VPC + regional subnet
- Cloud Router + Cloud NAT for outbound access
- 5 private application VMs: `web-1`, `web-2`, `db-node-1`, `db-node-2`, `db-node-3`
- 3 MongoDB data-bearing replica set nodes
- external HTTP load balancer for the web demo
- IAP SSH firewall for private VMs
- public control node for running Ansible in the VPC
- generated root `inventory.yaml`

## Structure

```text
terraform/
  main.tf
  outputs.tf
  variables.tf
  versions.tf
  inventory.tpl
  modules/
    network/
    nat/
    compute/
    load_balancer/
    control_node/
```

Module responsibilities:

- `network`: VPC, subnet, internal firewall, IAP SSH firewall.
- `nat`: Cloud Router and Cloud NAT.
- `compute`: private web/db VMs and reserved internal IPs.
- `load_balancer`: HTTP load balancer and health-check firewall.
- `control_node`: Ansible control VM, external IP, SSH firewall.

## Usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars

terraform init
terraform plan
terraform apply
```

After `apply`, Terraform regenerates `../inventory.yaml`.

Typical Ansible flow from the control node:

```bash
ansible all -m ping
ansible-playbook prepare.yaml
ansible-playbook setup_mongodb.yaml
ansible-playbook seed_data.yaml
ansible-playbook audit_mongodb8_l1.yaml -e audit_phase=before
```

## Access

Private application VMs do not have public IPs. You can SSH through IAP:

```bash
gcloud compute ssh ubuntu@db-node-1 --zone=us-central1-a --tunnel-through-iap
```

The control node has a public IP for the current lab workflow:

```bash
terraform output control_external_ip
```

For a safer demo, set `control_ssh_source_ranges` in `terraform.tfvars` to your
public IP `/32` instead of `0.0.0.0/0`.

## Notes

- The web load balancer is HTTP-only for now because the lab has no domain.
- The control node copies the SSH private key through instance metadata for lab
  convenience. This is not production-safe; use Secret Manager or IAP-only SSH
  for a hardened version.
- `terraform.tfvars`, `.terraform/`, and state files should stay out of git.
