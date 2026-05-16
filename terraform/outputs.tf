output "private_ips" {
  description = "Private IPs by host name."
  value       = module.compute.private_ips
}

output "web_lb_ip" {
  description = "Public load balancer IP."
  value       = module.load_balancer.web_lb_ip
}

output "web_url" {
  description = "Web demo URL."
  value       = module.load_balancer.web_url
}

output "control_external_ip" {
  description = "Control node external IP."
  value       = module.control_node.external_ip
}

output "vm_zones" {
  description = "VM zones by host name."
  value = {
    for name, host in var.hosts : name => host.zone
  }
}

output "ssh_via_iap_examples" {
  description = "Example SSH commands for app VMs through IAP."
  value = {
    for name, host in var.hosts :
    name => "gcloud compute ssh ${var.ssh_user}@${name} --zone=${host.zone} --tunnel-through-iap"
  }
}
