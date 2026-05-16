variable "network_name" {
  description = "VPC network name."
  type        = string
}

variable "subnet_name" {
  description = "Subnet name."
  type        = string
}

variable "subnet_cidr" {
  description = "Private subnet CIDR."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
}
