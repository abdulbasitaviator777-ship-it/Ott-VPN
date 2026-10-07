# OTT VPN — Terraform for Indian WireGuard Gateways
#
# Provisions WireGuard gateway VMs in India using cloud provider APIs.
# Requires provider credentials configured via environment variables.
#
# Supported regions:
#   AWS:  ap-south-1 (Mumbai), ap-south-2 (Hyderabad)
#   GCP:  asia-south1 (Mumbai), asia-south2 (Delhi)
#   Azure: centralindia (Pune), southindia (Chennai)
#
# Usage:
#   terraform init
#   terraform plan -var 'region=ap-south-1' -var 'city=Mumbai'
#   terraform apply -var 'region=ap-south-1' -var 'city=Mumbai'

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  description = "AWS region in India (e.g., ap-south-1 for Mumbai)"
  type        = string
  default     = "ap-south-1"
}

variable "city" {
  description = "City name for this gateway"
  type        = string
  default     = "Mumbai"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "ami_id" {
  description = "Ubuntu 22.04 LTS AMI ID (or auto-selected)"
  type        = string
  default     = ""
}

variable "ssh_key_name" {
  description = "Name of an existing EC2 key pair"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH to the gateway"
  type        = string
  default     = "0.0.0.0/0"
}

provider "aws" {
  region = var.region
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109093"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_security_group" "ottvpn_wg" {
  name        = "ottvpn-wg-${var.city}"
  description = "OTT VPN WireGuard gateway (${var.city})"

  ingress {
    description = "WireGuard UDP"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH (restricted)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "IPv6 WireGuard"
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_instance" "ottvpn_gateway" {
  ami                         = var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = var.ssh_key_name
  vpc_security_group_ids      = [aws_security_group.ottvpn_wg.id]
  associate_public_ip_address = true
  source_dest_check           = false

  tags = {
    Name        = "ottvpn-wg-${var.city}"
    Country     = "IN"
    City        = var.city
    Application = "ottvpn"
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }
}

output "server_id" {
  value = "in-${lower(replace(var.city, " ", ""))}-01"
}

output "public_ip" {
  value = aws_instance.ottvpn_gateway.public_ip
}

output "public_dns" {
  value = aws_instance.ottvpn_gateway.public_dns
}

output "region" {
  value = var.region
}

output "city" {
  value = var.city
}