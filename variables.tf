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

# variable "s3_bucket_name" {
#   description = "S3 Bucket Name"
#   type        = string
# }

variable "db_username" {
  description = "Database admin username"
  type        = string
  sensitive   = true
}

# variable "db_password" {
#   description = "Database admin password"
#   type        = string
#   sensitive   = true
# }

variable "demo_certificate_arn" {
  description = "ARN of the manually imported SSL certificate for the demo environment"
  type        = string
  default     = "" # optional: can leave empty if you're using tfvars
}

variable "db_name" {
  description = "The name of the database"
  type        = string
}

variable "db_dialect" {
  description = "The database"
  type        = string
}

variable "domain_name" {
  description = "Your registered domain name"
  type        = string
}

variable "subdomain" {
  description = "Your registered sub domain name"
  type        = string
}

variable "key_name" {
  description = "Your Key Name"
  type        = string
}
