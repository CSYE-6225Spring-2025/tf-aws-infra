variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "aws_profile" {
  description = "The AWS profile to use for deployment"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
}

variable "availability_zones" {
  description = "Availability zones for the subnets"
  type        = list(string)
}

variable "ami_id" {
  description = "The AMI ID for the EC2 instance"
  type        = string
}

variable "app_port" {
  description = "The port on which the application runs"
  type        = number
}
