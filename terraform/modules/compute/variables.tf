variable "hosts" {
  description = "Application VM definitions."
  type = map(object({
    ip           = string
    role         = string
    zone         = string
    machine_type = string
  }))
}

variable "region" {
  description = "GCP region."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for VM network interfaces."
  type        = string
}

variable "ssh_user" {
  description = "Linux SSH user."
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key content."
  type        = string
}

variable "image" {
  description = "Boot disk image."
  type        = string
}

variable "domain_suffix" {
  description = "Internal hostname suffix."
  type        = string
  default     = "automation-cis.local"
}
