output "external_ip" {
  description = "Control node external IP."
  value       = google_compute_address.control_external.address
}
