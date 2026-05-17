locals {
  web_zones = toset([
    for name, host in var.hosts : host.zone if host.role == "web"
  ])
}

resource "google_compute_instance_group" "web" {
  for_each = local.web_zones

  name = "automation-cis-web-ig-${each.key}"
  zone = each.key

  instances = [
    for name, host in var.hosts :
    var.instance_ids[name] if host.role == "web" && host.zone == each.key
  ]

  named_port {
    name = "http"
    port = 80
  }
}

resource "google_compute_health_check" "web" {
  name = "automation-cis-web-hc"

  http_health_check {
    port         = 80
    request_path = "/healthz"
  }

  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3
}

resource "google_compute_backend_service" "web" {
  name          = "automation-cis-web-backend"
  protocol      = "HTTP"
  port_name     = "http"
  timeout_sec   = 30
  health_checks = [google_compute_health_check.web.id]

  dynamic "backend" {
    for_each = google_compute_instance_group.web
    content {
      group           = backend.value.id
      balancing_mode  = "UTILIZATION"
      max_utilization = 0.8
    }
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

resource "google_compute_url_map" "web" {
  name            = "automation-cis-web-urlmap"
  default_service = google_compute_backend_service.web.id
}

resource "google_compute_target_http_proxy" "web" {
  name    = "automation-cis-web-http-proxy"
  url_map = google_compute_url_map.web.id
}

resource "google_compute_global_address" "web_lb_ip" {
  name = "automation-cis-web-lb-ip"
}

resource "google_compute_global_forwarding_rule" "web_http" {
  name                  = "automation-cis-web-http-fr"
  target                = google_compute_target_http_proxy.web.id
  port_range            = "80"
  ip_address            = google_compute_global_address.web_lb_ip.id
  load_balancing_scheme = "EXTERNAL"
}

resource "google_compute_firewall" "allow_lb_healthcheck" {
  name    = "automation-cis-allow-lb-hc"
  network = var.network_name

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["web"]
}
