terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  # Hardcoded credentials (Vulnerability)
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# Public S3 Bucket with no encryption
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "vulnerable-training-bucket-${random_id.bucket_suffix.hex}"
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_public_access_block" "vulnerable_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
}

# Overly permissive IAM policy
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.vulnerable_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Insecure Security Group - All ports open
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-security-group"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Publicly accessible RDS without encryption
resource "aws_db_instance" "vulnerable_db" {
  identifier           = "vulnerable-database"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "Password123!"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
}

# EC2 instance with sensitive data in user_data
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.vulnerable_profile.name
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
              export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
              export DB_PASSWORD=Password123!
              export API_KEY=sk-1234567890abcdef
              echo "admin:Password123!" > /tmp/credentials.txt
              EOF

  tags = {
    Name = "vulnerable-instance"
    Environment = "production"
    Secret = "hardcoded-secret-value"
  }
}

resource "aws_iam_instance_profile" "vulnerable_profile" {
  name = "vulnerable-instance-profile"
  role = aws_iam_role.vulnerable_role.name
}

# Unencrypted EBS volume
resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false

  tags = {
    Name = "vulnerable-volume"
  }
}

# IAM user with excessive permissions
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-user"
}

resource "aws_iam_user_policy_attachment" "user_admin" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "vulnerable_key" {
  user = aws_iam_user.vulnerable_user.name
}

# Outputs exposing sensitive information
output "database_password" {
  value     = aws_db_instance.vulnerable_db.password
  sensitive = false
}

output "access_key_id" {
  value = aws_iam_access_key.vulnerable_key.id
}

output "secret_access_key" {
  value     = aws_iam_access_key.vulnerable_key.secret
  sensitive = false
}

output "bucket_name" {
  value = aws_s3_bucket.vulnerable_bucket.bucket
}
