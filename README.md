# AWS Compliance Automation Framework

This project implements an automated compliance monitoring and remediation system on AWS using:
- AWS Config
- EventBridge
- Lambda (where applicable)
- SSM Automation
- CloudWatch Logs
- CloudTrail Logs
- SNS (optional)

---

## 🔍 Objective

To detect non-compliant AWS resources and automatically remediate them or log actions using native AWS services.

---

## 🧩 Components Used

- **AWS Config:** Detects compliance violations  
- **EventBridge:** Triggers actions on non-compliance  
- **Lambda:** Logs events to CloudWatch (used for S3)  
- **SSM Automation:** Executes remediation steps (used for EC2, SG, and CloudTrail)  
- **CloudWatch & CloudTrail:** Used for observability and auditability  

---

## ✅ Implemented Compliance Flows

### 1. CloudTrail Logging Compliance

- **Resource Type:** `AWS::CloudTrail::Trail`
- **Flow:**
  - AWS Config Rule (Lambda evaluation)
  - Detects non-compliance
  - EventBridge triggers SSM Automation
  - Logs actions to CloudWatch Logs and CloudTrail Logs

### 2. S3 Bucket Public Access Blocked

- **Resource Type:** `AWS::S3::Bucket`
- **Flow:**
  - AWS Config managed rule detects non-compliance
  - EventBridge rule triggers Lambda function
  - Lambda writes to CloudWatch Logs

### 3. Security Group SSH Open Access

- **Resource Type:** `AWS::EC2::SecurityGroup`
- **Flow:**
  - AWS Config managed rule detects non-compliance
  - EventBridge rule triggers SSM Automation remediation

### 4. EC2 Required Tags

- **Resource Type:** `AWS::EC2::Instance`
- **Flow:**
  - AWS Config managed rule detects non-compliance
  - EventBridge rule triggers SSM Automation to apply missing tags

---

## 🗂️ Folder Structure

```bash
aws-compliance-automation-framework/
│
├── Lambda_code/
│   ├── cloudtrail_evaluator.py
│   └── s3_public_access_logger.py
│
├── SSM_YAML/
│   ├── EnableCloudTrailLogging.yaml
│   ├── RevokeOpenSSHAccess.yaml
│   └── AddMissingEC2Tags.yaml
│
└── README.md
