variable "hosts" {
  description = "Application VM definitions."
  type = map(object({
    ip           = string
    role         = string
    zone         = string
    machine_type = string
  }))
}

variable "instance_ids" {
  description = "Compute instance IDs by host name."
  type        = map(string)
}

variable "network_name" {
  description = "VPC network name."
  type        = string
}
