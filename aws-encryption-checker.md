
# AWS Encryption Gap Analyzer

A high-performance, parallel security scanning tool that checks encryption configuration across AWS services. Built in Rust for speed and reliability.

## Features

- 🔍 Comprehensive encryption checks across multiple AWS services:
  - S3 Buckets
  - DynamoDB Tables
  - EFS File Systems
  - SNS Topics
  - SQS Queues
  - Lambda Functions
  - CloudTrail Trails
  - Elasticsearch Domains
  - Secrets Manager
  - Redshift Clusters
  - KMS Keys

- ⚡ Parallel scanning for maximum performance
- 📊 Real-time progress tracking
- 📝 Detailed JSON reports
- 🔐 Support for AWS profiles and regions
- 🎯 Severity-based issue categorization

## Installation

### Prerequisites

- Rust 1.70 or higher
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Appropriate AWS IAM permissions for scanning services

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/aws-encryption-checker
cd aws-encryption-checker

# Build the project
cargo build --release

# The binary will be available at target/release/aws-encryption-checker
```

### Cargo.toml Dependencies

```toml
[dependencies]
clap = { version = "4.0", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1.0", features = ["full"] }
futures = "0.3"
indicatif = "0.17"
aws-config = "1.0"
aws-sdk-s3 = "1.0"
aws-sdk-rds = "1.0"
aws-sdk-kms = "1.0"
aws-sdk-ebs = "1.0"
aws-sdk-ec2 = "1.0"
aws-sdk-dynamodb = "1.0"
aws-sdk-efs = "1.0"
aws-sdk-sns = "1.0"
aws-sdk-sqs = "1.0"
aws-sdk-lambda = "1.0"
aws-sdk-cloudtrail = "1.0"
aws-sdk-elasticsearch = "1.0"
aws-sdk-secretsmanager = "1.0"
aws-sdk-redshift = "1.0"
```

## Usage

### Basic Usage

```bash
# Run with default settings (us-east-1 region)
aws-encryption-checker

# Specify a different region
aws-encryption-checker -r us-west-2

# Save report to file
aws-encryption-checker -r us-west-2 -o report.json

# Use specific AWS profile
aws-encryption-checker -p my-profile -r eu-west-1
```

### Command Line Options

```
OPTIONS:
    -o, --output <FILE>     Output file for JSON report
    -r, --region <REGION>   AWS region to scan [default: us-east-1]
    -p, --profile <NAME>    AWS profile to use
    -h, --help             Print help information
    -V, --version          Print version information
```

## Sample Output

```json
{
  "timestamp": "2024-11-27T10:30:00Z",
  "region": "us-west-2",
  "gaps": [
    {
      "resource_id": "my-bucket",
      "resource_type": "S3",
      "issue": "No default encryption configured",
      "severity": "HIGH",
      "region": "us-west-2",
      "detected_at": "2024-11-27T10:30:00Z"
    }
  ],
  "summary": {
    "total_resources_scanned": 150,
    "total_gaps_found": 3,
    "high_severity_count": 1,
    "medium_severity_count": 2,
    "low_severity_count": 0,
    "gaps_by_service": {
      "S3": 1,
      "DynamoDB": 2
    }
  }
}
```

## Required AWS Permissions

The tool requires read-only permissions for the services it scans. Here's a minimal IAM policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetEncryptionConfiguration",
                "s3:GetBucketVersioning",
                "dynamodb:DescribeTable",
                "efs:DescribeFileSystems",
                "sns:GetTopicAttributes",
                "sqs:GetQueueAttributes",
                "lambda:ListFunctions",
                "cloudtrail:DescribeTrails",
                "es:DescribeElasticsearchDomain",
                "secretsmanager:ListSecrets",
                "redshift:DescribeClusters",
                "kms:GetKeyRotationStatus"
            ],
            "Resource": "*"
        }
    ]
}
```

## Security Considerations

- The tool requires read-only AWS credentials
- No modifications are made to your AWS resources
- Scan results are only stored locally
- Consider the network impact when scanning large environments
- Be mindful of AWS API rate limits

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is, without warranty of any kind. Always validate findings and consult AWS documentation for best practices in encryption configuration.

