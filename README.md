# AWS Encryption Checker

A comprehensive tool written in Rust to check encryption configurations across multiple AWS services.

## Features

- Parallel scanning of multiple AWS services
- Detailed encryption gap reporting
- Progress visualization for each service scan
- Support for multiple AWS regions
- JSON output format
- Support for AWS profiles

## Supported Services

- Amazon S3
- Amazon DynamoDB
- Amazon EFS
- Amazon SNS
- Amazon SQS
- Amazon RDS
- Amazon CloudTrail
- Amazon Elasticsearch
- Amazon Redshift
- AWS Lambda
- Amazon WorkSpaces
- Amazon ElastiCache
- Amazon DocumentDB
- Amazon Neptune
- Amazon Glacier
- And more...

## Installation

1. Ensure you have Rust installed (1.70.0 or later)
2. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-encryption-checker
cd aws-encryption-checker
```

3. Build the project:
```bash
cargo build --release
```

## Usage

```bash
# Basic usage with default region (us-east-1)
aws-encryption-checker

# Specify a different region
aws-encryption-checker --region eu-west-1

# Use a specific AWS profile
aws-encryption-checker --profile production

# Save output to a file
aws-encryption-checker --output report.json

# Combine options
aws-encryption-checker --region eu-west-1 --profile production --output report.json
```

## Output Format

The tool generates a JSON report containing:
- Timestamp of the scan
- AWS region scanned
- List of encryption gaps found
- Summary statistics
- Severity levels for each issue
- Recommendations for remediation

Example output:
```json
{
  "timestamp": "2024-11-27T10:00:00Z",
  "region": "us-east-1",
  "gaps": [
    {
      "service": "S3",
      "resource_id": "my-bucket",
      "resource_name": "my-bucket",
      "issue": "No default encryption configured",
      "severity": "HIGH",
      "recommendation": "Enable S3 default encryption using KMS or AES-256"
    }
  ],
  "summary": {
    "total_resources_scanned": 100,
    "total_gaps_found": 1,
    "gaps_by_severity": {
      "HIGH": 1
    },
    "gaps_by_service": {
      "S3": 1
    }
  }
}
```

## AWS Credentials

The tool uses the AWS SDK's default credential provider chain. You can authenticate using:
- Environment variables
- AWS credentials file
- IAM roles
- AWS SSO

Required IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetEncryptionConfiguration",
                "dynamodb:DescribeTable",
                "efs:DescribeFileSystems",
                // ... (full list in docs/iam-permissions.md)
            ],
            "Resource": "*"
        }
    ]
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.