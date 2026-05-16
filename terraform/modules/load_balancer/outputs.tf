output "web_lb_ip" {
  description = "Public load balancer IP."
  value       = google_compute_global_address.web_lb_ip.address
}

output "web_url" {
  description = "Web demo URL."
  value       = "http://${google_compute_global_address.web_lb_ip.address}"
}
