variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Default provider zone."
  type        = string
  default     = "us-central1-a"
}

variable "control_zone" {
  description = "Zone for the Ansible control node."
  type        = string
  default     = "us-central1-a"
}

variable "subnet_cidr" {
  description = "Private subnet CIDR."
  type        = string
  default     = "10.148.0.0/24"
}

variable "ssh_user" {
  description = "Linux SSH user used by Ansible."
  type        = string
  default     = "ubuntu"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key injected into VM metadata."
  type        = string
  default     = "../gcp-key.pub"
}

variable "ssh_private_key_path" {
  description = "Path to the SSH private key copied to the control node for the lab."
  type        = string
  default     = "../gcp-key.pem"
}

variable "control_ssh_source_ranges" {
  description = "CIDRs allowed to SSH to the control node."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "image" {
  description = "OS image for all VMs."
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "hosts" {
  description = "Application VM definitions."
  type = map(object({
    ip           = string
    role         = string
    zone         = string
    machine_type = string
  }))
  default = {
    "db-node-1" = {
      ip           = "10.148.0.2"
      role         = "db"
      zone         = "us-central1-a"
      machine_type = "e2-standard-2"
    }
    "db-node-2" = {
      ip           = "10.148.0.4"
      role         = "db"
      zone         = "us-central1-b"
      machine_type = "e2-standard-2"
    }
    "db-node-3" = {
      ip           = "10.148.0.5"
      role         = "db"
      zone         = "us-central1-c"
      machine_type = "e2-standard-2"
    }
    "web-1" = {
      ip           = "10.148.0.6"
      role         = "web"
      zone         = "us-central1-a"
      machine_type = "e2-small"
    }
    "web-2" = {
      ip           = "10.148.0.7"
      role         = "web"
      zone         = "us-central1-b"
      machine_type = "e2-small"
    }
  }
}
