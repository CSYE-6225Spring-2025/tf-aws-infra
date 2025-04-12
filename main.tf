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

  # ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  ingress {
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
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

# Generate random password for RDS
resource "random_password" "db_password" {
  length           = 16
  special          = false
  override_special = "!#$%&*()-_=+[]{}<>:?"
}


# Store password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password" {
  name        = "db-password-secret11"
  description = "Secret containing the RDS database password"
  kms_key_id  = aws_kms_key.kms_secrets_key.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}

resource "aws_db_instance" "app_db" {
  db_name                = var.db_name
  identifier             = "csye6225"
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = var.db_username
  password               = random_password.db_password.result
  parameter_group_name   = aws_db_parameter_group.mysql_parameter_group.name
  skip_final_snapshot    = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  multi_az               = false
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.kms_rds_key.arn
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

# # ✅ Separate resource for server-side encryption
# resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
#   bucket = aws_s3_bucket.app_bucket.id

#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "AES256"
#     }
#   }
# }


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

# Load Balancer Security Group
resource "aws_security_group" "lb_sg" {
  name        = "load-balancer-security-group"
  description = "Security group for Load Balancer"
  vpc_id      = aws_vpc.main.id

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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "load-balancer-security-group"
  }
}

# # Create EC2 Instance
# resource "aws_instance" "app_server" {
#   ami                         = var.ami_id
#   instance_type               = "t2.micro"
#   subnet_id                   = aws_subnet.public[0].id
#   vpc_security_group_ids      = [aws_security_group.app_sg.id]
#   iam_instance_profile        = aws_iam_instance_profile.ec2_s3_profile.name
#   associate_public_ip_address = true

#   user_data = <<-EOF
# #!/bin/bash

# exec > /var/log/user-data.log 2>&1

# echo "🚀 Starting user data execution..."

# # Ensure the application directory exists
# sudo mkdir -p /var/www/webapp
# sudo chown csye6225:csye6225 /var/www/webapp
# sudo chmod 755 /var/www/webapp

# # Create and write the .env file
# echo "📝 Writing environment variables to /var/www/webapp/.env..."
# sudo tee /var/www/webapp/.env > /dev/null << 'EOT'
# DB_HOST=${aws_db_instance.app_db.address}
# DB_USER=${var.db_username}
# DB_PASS=${var.db_password}
# DB_NAME=${var.db_name}
# DB_DIALECT=mysql
# AWS_REGION=${var.aws_region}
# S3_BUCKET_NAME=${aws_s3_bucket.app_bucket.bucket}
# EOT

# # Set permissions
# sudo chown csye6225:csye6225 /var/www/webapp/.env
# sudo chmod 644 /var/www/webapp/.env

# # Log success message correctly
# echo "✅ .env file created successfully!"

# # Configure CloudWatch agent
# echo "⚙️ Configuring CloudWatch agent..."
# sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
# sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null << 'EOT'
# {
#   "agent": {
#     "metrics_collection_interval": 60,
#     "run_as_user": "root"
#   },
#   "logs": {
#     "logs_collected": {
#       "files": {
#         "collect_list": [
#           {
#             "file_path": "/var/log/webapp/application.log",
#             "log_group_name": "webapp-logs",
#             "log_stream_name": "{instance_id}-application",
#             "retention_in_days": 7
#           },
#           {
#             "file_path": "/var/log/webapp/error.log",
#             "log_group_name": "webapp-logs",
#             "log_stream_name": "{instance_id}-error",
#             "retention_in_days": 7
#           },
#           {
#             "file_path": "/var/log/user-data.log",
#             "log_group_name": "webapp-logs",
#             "log_stream_name": "{instance_id}-user-data",
#             "retention_in_days": 7
#           }
#         ]
#       }
#     }
#   },
#   "metrics": {
#     "metrics_collected": {
#       "statsd": {
#         "service_address": ":8125",
#         "metrics_collection_interval": 10,
#         "metrics_aggregation_interval": 60
#       }
#     }
#   }
# }
# EOT

# # Create log directories if they don't exist
# sudo mkdir -p /var/log/webapp
# sudo chown csye6225:csye6225 /var/log/webapp
# sudo chmod 755 /var/log/webapp

# # Restart CloudWatch agent
# echo "🔄 Starting CloudWatch agent..."
# sudo systemctl restart amazon-cloudwatch-agent

# # Stop the service if it's already running (might be auto-started)
# sudo systemctl stop webapp || true

# # Restart webapp service
# echo "🔄 Restarting webapp service..."
# sudo systemctl daemon-reload
# sudo systemctl restart webapp

# echo "🎉 User data execution completed successfully!"
# EOF

#   root_block_device {
#     volume_size           = 25
#     volume_type           = "gp2"
#     delete_on_termination = true
#   }

#   tags = {
#     Name = "application-server"
#   }
# }


resource "aws_iam_policy" "secrets_access_policy" {
  name        = "ec2-secrets-access-policy"
  description = "Allows EC2 to retrieve secrets from Secret Manager"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
        Resource = [
          aws_secretsmanager_secret.db_password.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_secrets_attach" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.secrets_access_policy.arn
}

# Launch Template for Auto Scaling
resource "aws_launch_template" "app_launch_template" {
  name          = "csye6225_asg"
  image_id      = var.ami_id
  instance_type = "t2.micro"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_s3_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }

  user_data = base64encode(<<-EOF
#!/bin/bash

exec > /var/log/user-data.log 2>&1
set -e

echo "🚀 Starting user data execution..."


# Install required packages
echo "Installing required packages..."
sudo apt-get update -y
sudo apt-get install -y jq

# Install AWS CLI v2
echo "Installing AWS CLI v2..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version

# Set variables from Terraform
export RDS_SECRET_NAME="${aws_secretsmanager_secret.db_password.name}"
export DB_HOST="${aws_db_instance.app_db.address}"
export DB_USER="${var.db_username}"
export DB_NAME="${var.db_name}"
export APP_PORT="${var.app_port}"
export S3_BUCKET_NAME="${aws_s3_bucket.app_bucket.bucket}"
export AWS_REGION="${var.aws_region}"



echo "Fetching database password from Secret Manager..."
# Here $$ is needed to escape $ in bash variables
RDS_SECRET=$(aws secretsmanager get-secret-value --region $${AWS_REGION} --secret-id "$${RDS_SECRET_NAME}" --query SecretString --output text)
if [ $? -ne 0 ]; then
  echo "Error fetching RDS secret"
  # Fallback to using the direct password if secret retrieval fails
  DB_PASSWORD_FETCHED="${random_password.db_password.result}"
  echo "Using fallback password"
else
  echo "Secret retrieved successfully"
  DB_PASSWORD_FETCHED="$RDS_SECRET"
  echo "Password length: $${#DB_PASSWORD_FETCHED}"
fi

echo "DB_HOST=$${DB_HOST}"
echo "DB_USER=$${DB_USER}"
echo "DB_NAME=$${DB_NAME}"
echo "APP_PORT=$${APP_PORT}"
echo "S3_BUCKET_NAME=$${S3_BUCKET_NAME}"


# Ensure the application directory exists
sudo mkdir -p /var/www/webapp
sudo chown csye6225:csye6225 /var/www/webapp
sudo chmod 755 /var/www/webapp

# Create or update .env file
echo "Creating/updating .env file..."
sudo -u csye6225 bash -c "touch /var/www/webapp/.env"

# Update environment variables
sudo -u csye6225 bash -c "sed -i '/^DB_HOST=/d' /var/www/webapp/.env && echo \"DB_HOST=$${DB_HOST}\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^DB_USER=/d' /var/www/webapp/.env && echo \"DB_USER=$${DB_USER}\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^DB_PASS=/d' /var/www/webapp/.env && printf 'DB_PASS=%q\n' \"$${DB_PASSWORD_FETCHED}\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^DB_NAME=/d' /var/www/webapp/.env && echo \"DB_NAME=$${DB_NAME}\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^DB_DIALECT=/d' /var/www/webapp/.env && echo \"DB_DIALECT=mysql\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^AWS_REGION=/d' /var/www/webapp/.env && echo \"AWS_REGION=$${AWS_REGION}\" >> /var/www/webapp/.env"
sudo -u csye6225 bash -c "sed -i '/^S3_BUCKET_NAME=/d' /var/www/webapp/.env && echo \"S3_BUCKET_NAME=$${S3_BUCKET_NAME}\" >> /var/www/webapp/.env"

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
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "asg-application-server"
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "app_asg" {
  name                      = "app-auto-scaling-group"
  min_size                  = 3
  max_size                  = 5
  desired_capacity          = 3
  vpc_zone_identifier       = aws_subnet.public[*].id
  target_group_arns         = [aws_lb_target_group.app_tg.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  default_cooldown          = 60

  launch_template {
    id      = aws_launch_template.app_launch_template.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "asg-app-instance"
    propagate_at_launch = true
  }
}

# Auto Scaling Policies
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale-up-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1
  cooldown               = 60
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "8"
  alarm_description   = "Scale up when CPU exceeds 5%"
  alarm_actions       = [aws_autoscaling_policy.scale_up.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 60
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "6"
  alarm_description   = "Scale down when CPU is below 3%"
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

# Application Load Balancer
resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name = "app-load-balancer"
  }
}

resource "aws_lb_target_group" "app_tg" {
  name     = "app-target-group"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    interval            = 120
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    matcher             = "200"
  }
}

resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

data "aws_caller_identity" "current" {}

# EC2 KMS Key
resource "aws_kms_key" "kms_ec2_key" {
  description             = "KMS key for EC2 instances"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  rotation_period_in_days = 90
}

resource "aws_kms_alias" "kms_ec2_key_alias" {
  name          = "alias/ec2-key"
  target_key_id = aws_kms_key.kms_ec2_key.key_id
}

resource "aws_kms_key_policy" "kms_ec2_key_policy" {
  key_id = aws_kms_key.kms_ec2_key.key_id
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "kms-ec2-key-policy",
    Statement = [
      {
        Sid    = "EnableAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.ec2_s3_role.name}"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowAutoScalingServiceAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ],
        Resource = "*"
      }
    ]
  })
}


# RDS KMS Key
resource "aws_kms_key" "kms_rds_key" {
  description             = "KMS key for RDS instances"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  rotation_period_in_days = 90
}



resource "aws_kms_alias" "kms_rds_key_alias" {
  name          = "alias/rds-key"
  target_key_id = aws_kms_key.kms_rds_key.key_id
}

resource "aws_kms_key_policy" "kms_rds_key_policy" {
  key_id = aws_kms_key.kms_rds_key.key_id
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "kms-rds-key-policy",
    Statement = [
      {
        Sid    = "EnableAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowRDSServiceAccess",
        Effect = "Allow",
        Principal = {
          Service = "rds.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.ec2_s3_role.name}"
        },
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
}


# S3 KMS Key
resource "aws_kms_key" "kms_s3_key" {
  description             = "KMS key for S3 buckets"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  rotation_period_in_days = 90
}

resource "aws_kms_alias" "kms_s3_key_alias" {
  name          = "alias/s3-key"
  target_key_id = aws_kms_key.kms_s3_key.key_id
}

resource "aws_kms_key_policy" "kms_s3_key_policy" {
  key_id = aws_kms_key.kms_s3_key.key_id
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "kms-s3-key-policy",
    Statement = [
      {
        Sid    = "EnableAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowS3ServiceAccess",
        Effect = "Allow",
        Principal = {
          Service = "s3.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.ec2_s3_role.name}"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
}


# Secrets Manager KMS Key
resource "aws_kms_key" "kms_secrets_key" {
  description             = "KMS key for Secrets Manager"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  rotation_period_in_days = 90
}


resource "aws_kms_alias" "kms_secrets_key_alias" {
  name          = "alias/secrets-key"
  target_key_id = aws_kms_key.kms_secrets_key.key_id
}

resource "aws_kms_key_policy" "kms_secrets_key_policy" {
  key_id = aws_kms_key.kms_secrets_key.key_id
  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "kms-secrets-key-policy",
    Statement = [
      {
        Sid    = "EnableAccountAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "AllowSecretsManagerServiceAccess",
        Effect = "Allow",
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "AllowEC2RoleAccess",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${aws_iam_role.ec2_s3_role.name}"
        },
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.kms_s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}



data "aws_route53_zone" "primary" {
  name = "${var.subdomain}.${var.domain_name}"
}

resource "aws_route53_record" "alb_record" {
  zone_id = data.aws_route53_zone.primary.zone_id
  name    = "${var.subdomain}.${var.domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}

locals {
  is_demo_profile = var.aws_profile == "Demo-User"
  certificate_arn = local.is_demo_profile ? var.demo_certificate_arn : aws_acm_certificate.dev_certificate[0].arn
}

resource "aws_acm_certificate" "dev_certificate" {
  count             = var.aws_profile == "Demo-User" ? 0 : 1
  domain_name       = "${var.subdomain}.${var.domain_name}"
  validation_method = "DNS"
  tags = {
    Name = "dev-ssl-certificate"
  }
}

resource "aws_route53_record" "dev_cert_validation_record" {
  for_each = var.aws_profile == "Demo-User" ? {} : {
    for dvo in aws_acm_certificate.dev_certificate[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  type            = each.value.type
  ttl             = 60
  zone_id         = data.aws_route53_zone.primary.zone_id
}

resource "aws_acm_certificate_validation" "dev_cert_validation" {
  count                   = var.aws_profile == "Demo-User" ? 0 : 1
  certificate_arn         = aws_acm_certificate.dev_certificate[0].arn
  validation_record_fqdns = [for record in aws_route53_record.dev_cert_validation_record : record.fqdn]
}




resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}
