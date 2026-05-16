resource "google_compute_address" "internal" {
  for_each     = var.hosts
  name         = "ip-${each.key}"
  subnetwork   = var.subnet_id
  address_type = "INTERNAL"
  address      = each.value.ip
  region       = var.region
}

resource "google_compute_instance" "vm" {
  for_each = var.hosts

  name         = each.key
  machine_type = each.value.machine_type
  zone         = each.value.zone
  hostname     = "${each.key}.${var.domain_suffix}"
  tags         = each.value.role == "web" ? ["web"] : ["internal"]

  boot_disk {
    initialize_params {
      image = var.image
      size  = 20
    }
  }

  network_interface {
    subnetwork = var.subnet_id
    network_ip = google_compute_address.internal[each.key].address
  }

  metadata = {
    ssh-keys = "${var.ssh_user}:${var.ssh_public_key}"
  }

  allow_stopping_for_update = true
}
