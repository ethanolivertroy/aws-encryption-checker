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

## Requirements

- Rust 1.70.0 or later
- AWS credentials configured (via environment variables, AWS credentials file, IAM roles, or AWS SSO)
- Appropriate AWS IAM permissions (see AWS Credentials section below)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/aws-encryption-checker
cd aws-encryption-checker
```

2. Build the project:
```bash
cargo build --release
```

The compiled binary will be available at `target/release/aws-encryption-checker`

## Usage

```bash
# Run directly with cargo
cargo run -- [OPTIONS]

# Or use the compiled binary
./target/release/aws-encryption-checker [OPTIONS]

# Basic usage with default region (us-east-1)
./target/release/aws-encryption-checker

# Specify a different region
./target/release/aws-encryption-checker --region eu-west-1

# Use a specific AWS profile
./target/release/aws-encryption-checker --profile production

# Save output to a file
./target/release/aws-encryption-checker --output report.json

# Combine options
./target/release/aws-encryption-checker --region eu-west-1 --profile production --output report.json

# Enable debug logging
./target/release/aws-encryption-checker --debug

# Enable verbose logging
./target/release/aws-encryption-checker --verbose
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
                "s3:ListBuckets",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "efs:DescribeFileSystems",
                "sns:ListTopics",
                "sns:GetTopicAttributes",
                "sqs:ListQueues",
                "sqs:GetQueueAttributes",
                "lambda:ListFunctions",
                "lambda:GetFunctionConfiguration",
                "cloudtrail:DescribeTrails",
                "es:ListDomainNames",
                "es:DescribeDomain",
                "redshift:DescribeClusters",
                "docdb:DescribeDBClusters",
                "neptune:DescribeDBClusters",
                "glacier:ListVaults",
                "glacier:DescribeVault"
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