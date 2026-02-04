# Vulnerable Flask Application - Security Training

⚠️ **WARNING: This application is intentionally vulnerable and should ONLY be used for security training, demonstrations, and testing in isolated environments. DO NOT deploy to production or expose to the internet.**

## Overview

This is a deliberately vulnerable Flask application designed to demonstrate common security vulnerabilities and AWS misconfigurations for educational purposes.

## Application Vulnerabilities

### 1. SQL Injection
- **Location**: `/search` endpoint
- **Exploit**: `?q=' OR '1'='1`
- **Description**: User input is directly concatenated into SQL queries

### 2. Cross-Site Scripting (XSS)
- **Location**: `/comment` endpoint
- **Exploit**: `<script>alert('XSS')</script>`
- **Description**: User input is rendered without sanitization

### 3. Insecure Direct Object References (IDOR)
- **Location**: `/document` endpoint
- **Exploit**: Change `?id=1` to `?id=2` to access other users' documents
- **Description**: No authorization checks on document access

### 4. Command Injection
- **Location**: `/ping` endpoint
- **Exploit**: `127.0.0.1; cat /etc/passwd`
- **Description**: User input passed directly to shell commands

### 5. Weak Authentication
- **Location**: `/login` endpoint
- **Credentials**: admin/admin123 or user/password
- **Description**: SQL injection in login form

### 6. Hardcoded Credentials
- **Location**: Throughout `app.py`
- **Description**: AWS keys, database passwords, and secret keys hardcoded in source

### 7. Insecure File Uploads
- **Location**: `/upload` endpoint
- **Exploit**: Upload any file type including executables
- **Description**: No validation on file type or content

### 8. Information Disclosure
- **Location**: `/info` endpoint
- **Description**: Exposes AWS credentials, database passwords, and environment variables

### 9. Unvalidated Redirects
- **Location**: `/redirect` endpoint
- **Exploit**: `?url=https://malicious-site.com`
- **Description**: No validation of redirect URLs

### 10. Plaintext Password Storage
- **Location**: Database
- **Description**: Passwords stored without hashing

## AWS/Infrastructure Vulnerabilities

### CloudFormation Template (`vulnerable-cloudformation.yaml`)
- Public S3 buckets with full public access
- Overly permissive IAM roles with AdministratorAccess
- Publicly accessible RDS databases without encryption
- Security groups allowing all traffic from 0.0.0.0/0
- Hardcoded credentials in EC2 UserData
- Unencrypted EBS volumes
- IAM access keys exposed in outputs

### Terraform Configuration (`vulnerable-terraform.tf`)
- Hardcoded AWS credentials in provider block
- Public S3 buckets without encryption
- Excessive IAM permissions
- Open security groups (0.0.0.0/0)
- Publicly accessible databases
- Unencrypted storage
- Sensitive data in EC2 user_data
- Secrets exposed in outputs

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The application will be available at `http://localhost:5000`

## Testing Endpoints

- `/` - Home page with links to all vulnerable endpoints
- `/login` - Vulnerable login form
- `/search` - SQL injection demo
- `/comment` - XSS demo
- `/document?id=1` - IDOR demo
- `/ping` - Command injection demo
- `/upload` - Insecure file upload
- `/info` - Information disclosure
- `/redirect?url=` - Unvalidated redirect

## Security Tools Testing

This application can be used to test:
- Static Application Security Testing (SAST) tools
- Dynamic Application Security Testing (DAST) tools
- Infrastructure as Code (IaC) scanners
- Secret detection tools
- Dependency vulnerability scanners
- AWS security assessment tools

## Recommended Security Scanners

- **SAST**: Bandit, Semgrep, SonarQube
- **IaC**: Checkov, tfsec, cfn-nag, Prowler
- **Secrets**: TruffleHog, GitLeaks, detect-secrets
- **DAST**: OWASP ZAP, Burp Suite, Nikto
- **AWS**: AWS Security Hub, ScoutSuite, Prowler

## Disclaimer

This application is for educational purposes only. The vulnerabilities are intentional and should never be replicated in production systems. Always follow security best practices when developing real applications.
