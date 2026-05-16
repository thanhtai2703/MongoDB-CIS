output "private_ips" {
  description = "Private IPs by host name."
  value = {
    for name, vm in google_compute_instance.vm :
    name => vm.network_interface[0].network_ip
  }
}

output "instance_ids" {
  description = "Compute instance IDs by host name."
  value = {
    for name, vm in google_compute_instance.vm :
    name => vm.id
  }
}
