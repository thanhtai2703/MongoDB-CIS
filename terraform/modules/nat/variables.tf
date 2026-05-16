variable "router_name" {
  description = "Cloud Router name."
  type        = string
}

variable "nat_name" {
  description = "Cloud NAT name."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
}

variable "network_id" {
  description = "VPC network ID."
  type        = string
}
