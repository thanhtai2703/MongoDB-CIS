variable "region" {
  description = "GCP region."
  type        = string
}

variable "zone" {
  description = "Control node zone."
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the control node."
  type        = string
}

variable "network_name" {
  description = "VPC network name."
  type        = string
}

variable "image" {
  description = "Boot disk image."
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

variable "ssh_private_key" {
  description = "SSH private key content copied to the control node for lab convenience."
  type        = string
}

variable "control_ssh_source_ranges" {
  description = "CIDRs allowed to SSH to the control node."
  type        = list(string)
}
