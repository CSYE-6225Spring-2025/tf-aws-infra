provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# Create VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.vpc_name
  }
}

# Create Public Subnets
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = element(var.public_subnet_cidrs, count.index)
  map_public_ip_on_launch = true
  availability_zone       = element(var.availability_zones, count.index)

  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

# Create Private Subnets
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.private_subnet_cidrs, count.index)
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = "private-subnet-${count.index + 1}"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "ig1"
  }
}

# Create Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "public-route-table-1"
  }
}

# Attach Public Subnets to Public Route Table
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Create Route for Public Route Table
resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

# Create Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "private-route-table-1"
  }
}

# Attach Private Subnets to Private Route Table
resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}



# Create Application Security Group
resource "aws_security_group" "app_sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "application-security-group"
  }
}

# Create RDS Parameter Group
resource "aws_db_parameter_group" "mysql_parameter_group" {
  name        = "mysql-parameter-group"
  family      = "mysql8.0"
  description = "Custom MySQL parameter group"

  parameter {
    name  = "log_bin_trust_function_creators"
    value = "1"
  }

  parameter {
    name  = "max_connections"
    value = "200"
  }

  tags = {
    Name = "mysql-parameter-group"
  }
}

# Create RDS Subnet Group
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "db-subnet-group"
  }
}

# Create RDS Instance and security group
resource "aws_security_group" "rds_sg" {
  name        = "rds-security-group"
  description = "Allow access only from EC2"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  egress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}

resource "aws_db_instance" "app_db" {
  db_name                = var.db_name
  identifier             = "csye6225"
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = aws_db_parameter_group.mysql_parameter_group.name
  skip_final_snapshot    = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  multi_az               = false
  storage_encrypted      = true
}


# Create S3 Bucket
resource "random_uuid" "s3_bucket_name" {}




###############################################
# 1) Assume-Role Policy Document for EC2
###############################################
data "aws_iam_policy_document" "ec2_assume_role_doc" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

###############################################
# 2) Create the IAM Role for EC2
###############################################
resource "aws_iam_role" "ec2_s3_role" {
  name               = "ec2-s3-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_doc.json
}

###############################################
# 3) S3 Access Policy
###############################################
resource "aws_iam_policy" "s3_access_policy" {
  name        = "ec2-s3-access-policy"
  description = "Allows EC2 to list, get, put, and delete objects in our S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        Resource = [
          # Replace 'my-bucket-name' with your actual bucket name
          "arn:aws:s3:::${aws_s3_bucket.app_bucket.id}",
          "arn:aws:s3:::${aws_s3_bucket.app_bucket.id}/*"
        ]
      }
    ]
  })
}

###############################################
# 4) Attach the S3 Policy to the EC2 Role
###############################################
resource "aws_iam_role_policy_attachment" "ec2_s3_attach" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

###############################################
# 5) Create an Instance Profile for That Role
###############################################
resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = "ec2-s3-instance-profile"
  role = aws_iam_role.ec2_s3_role.name
}

# Create Bucket
resource "aws_s3_bucket" "app_bucket" {
  bucket        = "my-app-bucket-${random_uuid.s3_bucket_name.result}"
  force_destroy = true # Allows Terraform to delete the bucket if needed

  tags = {
    Name = "app-bucket"
  }
}

# ✅ Separate resource for server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# ✅ Lifecycle rule (Objects transition to STANDARD_IA after 30 days)
resource "aws_s3_bucket_lifecycle_configuration" "app_bucket_lifecycle" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    id     = "transition-to-IA"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}


# CloudWatch Agent IAM Role
resource "aws_iam_role" "cloudwatch_agent_role" {
  name = "cloudwatch-agent-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

# CloudWatch Agent Policy
resource "aws_iam_policy" "cloudwatch_agent_policy" {
  name        = "cloudwatch-agent-policy"
  description = "Policy for CloudWatch Agent on EC2"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:CreateLogGroup",
          "logs:DescribeLogGroups",
          "cloudwatch:PutMetricData",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetMetricData",
          "ssm:GetParameter",
          "ec2:DescribeTags",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach CloudWatch Policy to your existing EC2 role
resource "aws_iam_role_policy_attachment" "attach_cloudwatch_policy" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.cloudwatch_agent_policy.arn
}

# Create EC2 Instance
resource "aws_instance" "app_server" {
  ami                         = var.ami_id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.app_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_s3_profile.name
  associate_public_ip_address = true

  user_data = <<-EOF
#!/bin/bash

exec > /var/log/user-data.log 2>&1

echo "🚀 Starting user data execution..."

# Ensure the application directory exists
sudo mkdir -p /var/www/webapp
sudo chown csye6225:csye6225 /var/www/webapp
sudo chmod 755 /var/www/webapp

# Create and write the .env file
echo "📝 Writing environment variables to /var/www/webapp/.env..."
sudo tee /var/www/webapp/.env > /dev/null << 'EOT'
DB_HOST=${aws_db_instance.app_db.address}
DB_USER=${var.db_username}
DB_PASS=${var.db_password}
DB_NAME=${var.db_name}
DB_DIALECT=mysql
AWS_REGION=${var.aws_region}
S3_BUCKET_NAME=${aws_s3_bucket.app_bucket.bucket}
EOT

# Set permissions
sudo chown csye6225:csye6225 /var/www/webapp/.env
sudo chmod 644 /var/www/webapp/.env

# Log success message correctly
echo "✅ .env file created successfully!"

# Configure CloudWatch agent
echo "⚙️ Configuring CloudWatch agent..."
sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null << 'EOT'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/webapp/application.log",
            "log_group_name": "webapp-logs",
            "log_stream_name": "{instance_id}-application",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/webapp/error.log",
            "log_group_name": "webapp-logs",
            "log_stream_name": "{instance_id}-error",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "webapp-logs",
            "log_stream_name": "{instance_id}-user-data",
            "retention_in_days": 7
          }
        ]
      }
    }
  },
  "metrics": {
    "metrics_collected": {
      "statsd": {
        "service_address": ":8125",
        "metrics_collection_interval": 10,
        "metrics_aggregation_interval": 60
      }
    }
  }
}
EOT

# Create log directories if they don't exist
sudo mkdir -p /var/log/webapp
sudo chown csye6225:csye6225 /var/log/webapp
sudo chmod 755 /var/log/webapp

# Restart CloudWatch agent
echo "🔄 Starting CloudWatch agent..."
sudo systemctl restart amazon-cloudwatch-agent

# Stop the service if it's already running (might be auto-started)
sudo systemctl stop webapp || true

# Restart webapp service
echo "🔄 Restarting webapp service..."
sudo systemctl daemon-reload
sudo systemctl restart webapp

echo "🎉 User data execution completed successfully!"
EOF

  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "application-server"
  }
}

resource "aws_route53_zone" "dev_zone" {
  count = var.aws_profile == "UserDev" ? 1 : 0
  name  = "dev.${var.domain_name}"
}

resource "aws_route53_zone" "demo_zone" {
  count = var.aws_profile == "Demo-User" ? 1 : 0
  name  = "demo.${var.domain_name}"
}

resource "aws_route53_record" "dev_a_record" {
  count   = var.aws_profile == "UserDev" ? 1 : 0
  zone_id = aws_route53_zone.dev_zone[0].zone_id
  name    = "dev.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.app_server.public_ip]
}

resource "aws_route53_record" "demo_a_record" {
  count   = var.aws_profile == "Demo-User" ? 1 : 0
  zone_id = aws_route53_zone.demo_zone[0].zone_id
  name    = "demo.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.app_server.public_ip]
}
