# OTT VPN — Multi-region Indian gateways
# This module deploys WireGuard gateways across multiple Indian cities.

module "mumbai" {
  source          = "./"
  city            = "Mumbai"
  region          = "ap-south-1"
  instance_type   = "t3.medium"
  ssh_key_name    = var.ssh_key_name
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

module "delhi" {
  source          = "./"
  city            = "Delhi"
  region          = "ap-south-2"
  instance_type   = "t3.medium"
  ssh_key_name    = var.ssh_key_name
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

module "hyderabad" {
  source          = "./"
  city            = "Hyderabad"
  region          = "ap-south-2"
  instance_type   = "t3.medium"
  ssh_key_name    = var.ssh_key_name
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

module "bangalore" {
  source          = "./"
  city            = "Bangalore"
  region          = "ap-south-1"
  instance_type   = "t3.medium"
  ssh_key_name    = var.ssh_key_name
  allowed_ssh_cidr = var.allowed_ssh_cidr
}