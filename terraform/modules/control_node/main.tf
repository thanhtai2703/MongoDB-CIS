resource "google_compute_address" "control_external" {
  name   = "automation-cis-control-ip"
  region = var.region
}

resource "google_compute_instance" "control" {
  name         = "control-node"
  machine_type = "e2-medium"
  zone         = var.zone
  hostname     = "control-node.automation-cis.local"
  tags         = ["control"]

  boot_disk {
    initialize_params {
      image = var.image
      size  = 20
    }
  }

  network_interface {
    subnetwork = var.subnet_id

    access_config {
      nat_ip = google_compute_address.control_external.address
    }
  }

  metadata = {
    ssh-keys = "${var.ssh_user}:${var.ssh_public_key}"

    startup-script = <<-EOF
      #!/bin/bash
      set -e

      # 1. Cập nhật hệ thống
      apt-get update -qq

      # 2. Cài Ansible
      apt-get install -y software-properties-common
      add-apt-repository --yes --update ppa:ansible/ansible
      apt-get install -y ansible git curl unzip

      # 3. Cài Ansible collection community.general (cần cho module ufw)
      ansible-galaxy collection install community.general --upgrade

      # 4. Cài gcloud SDK
      curl -sSL https://sdk.cloud.google.com -o /tmp/install_gcloud.sh
      bash /tmp/install_gcloud.sh --disable-prompts --install-dir=/opt/google-cloud-sdk
      ln -sf /opt/google-cloud-sdk/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud

      # 5. Ghi private key (được truyền qua metadata — xem control_ssh_private_key)
      mkdir -p /home/${var.ssh_user}/automation-cis
      echo "$(curl -sf -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh_private_key)" \
        > /home/${var.ssh_user}/automation-cis/gcp-key.pem
      chmod 600 /home/${var.ssh_user}/automation-cis/gcp-key.pem
      chown ${var.ssh_user}:${var.ssh_user} /home/${var.ssh_user}/automation-cis/gcp-key.pem

      echo "control-node ready" > /tmp/startup-done
    EOF

    ssh_private_key = var.ssh_private_key
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  allow_stopping_for_update = true
}

resource "google_compute_firewall" "allow_ssh_control" {
  name    = "automation-cis-allow-ssh-control"
  network = var.network_name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.control_ssh_source_ranges
  target_tags   = ["control"]
}
