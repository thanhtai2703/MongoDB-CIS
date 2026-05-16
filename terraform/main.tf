locals {
  ssh_public_key  = trimspace(file(var.ssh_public_key_path))
  ssh_private_key = file(var.ssh_private_key_path)
}

module "network" {
  source = "./modules/network"

  network_name = "automation-cis-vpc"
  subnet_name  = "automation-cis-subnet"
  subnet_cidr  = var.subnet_cidr
  region       = var.region
}

module "nat" {
  source = "./modules/nat"

  router_name = "automation-cis-router"
  nat_name    = "automation-cis-nat"
  region      = var.region
  network_id  = module.network.network_id
}

module "compute" {
  source = "./modules/compute"

  hosts          = var.hosts
  region         = var.region
  subnet_id      = module.network.subnet_id
  ssh_user       = var.ssh_user
  ssh_public_key = local.ssh_public_key
  image          = var.image
}

module "load_balancer" {
  source = "./modules/load_balancer"

  hosts        = var.hosts
  instance_ids = module.compute.instance_ids
  network_name = module.network.network_name
}

module "control_node" {
  source = "./modules/control_node"

  region                    = var.region
  zone                      = var.control_zone
  subnet_id                 = module.network.subnet_id
  network_name              = module.network.network_name
  image                     = var.image
  ssh_user                  = var.ssh_user
  ssh_public_key            = local.ssh_public_key
  ssh_private_key           = local.ssh_private_key
  control_ssh_source_ranges = var.control_ssh_source_ranges
}

resource "local_file" "ansible_inventory" {
  filename = "${path.module}/../inventory.yaml"
  content = templatefile("${path.module}/inventory.tpl", {
    hosts    = var.hosts
    ssh_user = var.ssh_user
  })
  file_permission = "0644"
}
