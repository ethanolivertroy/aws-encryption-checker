use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_rds::Client as RdsClient;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ebs::Client as EbsClient;
use aws_sdk_ec2::Client as Ec2Client;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_efs::Client as EfsClient;
use aws_sdk_sns::Client as SnsClient;
use aws_sdk_sqs::Client as SqsClient;
use aws_sdk_lambda::Client as LambdaClient;
use aws_sdk_cloudtrail::Client as CloudTrailClient;
use aws_sdk_elasticsearch::Client as ElasticsearchClient;
use aws_sdk_secretsmanager::Client as SecretsClient;
use aws_sdk_redshift::Client as RedshiftClient;
use clap::Parser;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use tokio;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long, value_parser)]
    output: Option<PathBuf>,

    #[clap(short, long, value_parser, default_value = "us-east-1")]
    region: String,

    #[clap(short, long)]
    profile: Option<String>,

    #[clap(short, long)]
    parallel: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptionGap {
    resource_id: String,
    resource_type: String,
    issue: String,
    severity: String,
    region: String,
    detected_at: DateTime<Utc>,
    additional_info: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanReport {
    timestamp: DateTime<Utc>,
    region: String,
    gaps: Vec<EncryptionGap>,
    summary: Summary,
}

#[derive(Debug, Serialize, Deserialize)]
struct Summary {
    total_resources_scanned: u32,
    total_gaps_found: u32,
    high_severity_count: u32,
    medium_severity_count: u32,
    low_severity_count: u32,
    gaps_by_service: std::collections::HashMap<String, u32>,
}

async fn check_s3_encryption(client: &S3Client, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let buckets = client.list_buckets().send().await?;

    for bucket in buckets.buckets().unwrap_or_default() {
        let bucket_name = bucket.name().unwrap_or_default();
        
        // Check default encryption
        let encryption = client.get_bucket_encryption()
            .bucket(bucket_name)
            .send()
            .await;

        if encryption.is_err() {
            gaps.push(EncryptionGap {
                resource_id: bucket_name.to_string(),
                resource_type: "S3".to_string(),
                issue: "No default encryption configured".to_string(),
                severity: "HIGH".to_string(),
                region: region.to_string(),
                detected_at: Utc::now(),
                additional_info: None,
            });
        }

        // Check versioning
        let versioning = client.get_bucket_versioning()
            .bucket(bucket_name)
            .send()
            .await?;

        if versioning.status().is_none() {
            gaps.push(EncryptionGap {
                resource_id: bucket_name.to_string(),
                resource_type: "S3".to_string(),
                issue: "Versioning not enabled".to_string(),
                severity: "MEDIUM".to_string(),
                region: region.to_string(),
                detected_at: Utc::now(),
                additional_info: None,
            });
        }
    }

    Ok(gaps)
}

async fn check_dynamodb_encryption(client: &DynamoClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let tables = client.list_tables().send().await?;

    for table_name in tables.table_names().unwrap_or_default() {
        let table_desc = client.describe_table()
            .table_name(table_name)
            .send()
            .await?;

        if let Some(table) = table_desc.table() {
            if let Some(sse_desc) = table.sse_description() {
                if sse_desc.status() != Some(&aws_sdk_dynamodb::types::SSEStatus::Enabled) {
                    gaps.push(EncryptionGap {
                        resource_id: table_name.to_string(),
                        resource_type: "DynamoDB".to_string(),
                        issue: "Server-side encryption not enabled".to_string(),
                        severity: "HIGH".to_string(),
                        region: region.to_string(),
                        detected_at: Utc::now(),
                        additional_info: None,
                    });
                }
            }
        }
    }

    Ok(gaps)
}

async fn check_efs_encryption(client: &EfsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let file_systems = client.describe_file_systems().send().await?;

    for fs in file_systems.file_systems().unwrap_or_default() {
        if let Some(fs_id) = fs.file_system_id() {
            if !fs.encrypted() {
                gaps.push(EncryptionGap {
                    resource_id: fs_id.to_string(),
                    resource_type: "EFS".to_string(),
                    issue: "Encryption at rest not enabled".to_string(),
                    severity: "HIGH".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_sns_encryption(client: &SnsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let topics = client.list_topics().send().await?;

    for topic in topics.topics().unwrap_or_default() {
        if let Some(topic_arn) = topic.topic_arn() {
            let attrs = client.get_topic_attributes()
                .topic_arn(topic_arn)
                .send()
                .await?;

            if !attrs.attributes().contains_key("KmsMasterKeyId") {
                gaps.push(EncryptionGap {
                    resource_id: topic_arn.to_string(),
                    resource_type: "SNS".to_string(),
                    issue: "Server-side encryption not configured".to_string(),
                    severity: "MEDIUM".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_sqs_encryption(client: &SqsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let queues = client.list_queues().send().await?;

    for queue_url in queues.queue_urls().unwrap_or_default() {
        let attrs = client.get_queue_attributes()
            .queue_url(queue_url)
            .attribute_names(aws_sdk_sqs::types::QueueAttributeName::All)
            .send()
            .await?;

        if !attrs.attributes().contains_key("KmsMasterKeyId") {
            gaps.push(EncryptionGap {
                resource_id: queue_url.to_string(),
                resource_type: "SQS".to_string(),
                issue: "Server-side encryption not configured".to_string(),
                severity: "MEDIUM".to_string(),
                region: region.to_string(),
                detected_at: Utc::now(),
                additional_info: None,
            });
        }
    }

    Ok(gaps)
}

async fn check_lambda_encryption(client: &LambdaClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut req = client.list_functions();
        if let Some(m) = marker.as_ref() {
            req = req.marker(m);
        }

        let response = req.send().await?;
        
        for function in response.functions().unwrap_or_default() {
            if let Some(config) = function.environment() {
                if config.kms_key_arn().is_none() {
                    gaps.push(EncryptionGap {
                        resource_id: function.function_name().unwrap_or_default().to_string(),
                        resource_type: "Lambda".to_string(),
                        issue: "Environment variables not encrypted with KMS".to_string(),
                        severity: "MEDIUM".to_string(),
                        region: region.to_string(),
                        detected_at: Utc::now(),
                        additional_info: None,
                    });
                }
            }
        }

        marker = response.next_marker().map(String::from);
        if marker.is_none() {
            break;
        }
    }

    Ok(gaps)
}

async fn check_cloudtrail_encryption(client: &CloudTrailClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let trails = client.describe_trails().send().await?;

    for trail in trails.trail_list().unwrap_or_default() {
        if let Some(name) = trail.name() {
            if trail.kms_key_id().is_none() {
                gaps.push(EncryptionGap {
                    resource_id: name.to_string(),
                    resource_type: "CloudTrail".to_string(),
                    issue: "Log encryption not enabled".to_string(),
                    severity: "HIGH".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_elasticsearch_encryption(client: &ElasticsearchClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let domains = client.list_domain_names().send().await?;

    for domain in domains.domain_names().unwrap_or_default() {
        if let Some(domain_name) = domain.domain_name() {
            let config = client.describe_elasticsearch_domain()
                .domain_name(domain_name)
                .send()
                .await?;

            if let Some(domain_status) = config.domain_status() {
                if !domain_status.encryption_at_rest_options().unwrap_or_default().enabled() {
                    gaps.push(EncryptionGap {
                        resource_id: domain_name.to_string(),
                        resource_type: "Elasticsearch".to_string(),
                        issue: "Encryption at rest not enabled".to_string(),
                        severity: "HIGH".to_string(),
                        region: region.to_string(),
                        detected_at: Utc::now(),
                        additional_info: None,
                    });
                }
            }
        }
    }

    Ok(gaps)
}

async fn check_secrets_encryption(client: &SecretsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let secrets = client.list_secrets().send().await?;

    for secret in secrets.secret_list().unwrap_or_default() {
        if let Some(arn) = secret.arn() {
            if secret.kms_key_id().is_none() {
                gaps.push(EncryptionGap {
                    resource_id: arn.to_string(),
                    resource_type: "Secrets Manager".to_string(),
                    issue: "Using default KMS key instead of custom key".to_string(),
                    severity: "LOW".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_redshift_encryption(client: &RedshiftClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let clusters = client.describe_clusters().send().await?;

    for cluster in clusters.clusters().unwrap_or_default() {
        if let Some(cluster_id) = cluster.cluster_identifier() {
            if !cluster.encrypted() {
                gaps.push(EncryptionGap {
                    resource_id: cluster_id.to_string(),
                    resource_type: "Redshift".to_string(),
                    issue: "Cluster encryption not enabled".to_string(),
                    severity: "HIGH".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_kms_key_rotation(client: &KmsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let keys = client.list_keys().send().await?;

    for key in keys.keys().unwrap_or_default() {
        if let Some(key_id) = key.key_id() {
            let rotation_status = client.get_key_rotation_status()
                .key_id(key_id)
                .send()
                .await?;

            if !rotation_status.key_rotation_enabled() {
                gaps.push(EncryptionGap {
                    resource_id: key_id.to_string(),
                    resource_type: "KMS".to_string(),
                    issue: "Key rotation not enabled".to_string(),
                    severity: "MEDIUM".to_string(),
                    region: region.to_string(),
                    detected_at: Utc::now(),
                    additional_info: None,
                });
            }
        }
    }

    Ok(gaps)
}

fn generate_summary(gaps: &[EncryptionGap]) -> Summary {
    let mut summary = Summary {
        total_resources_scanned: 0,
        total_gaps_found: gaps.len() as u32,
        high_severity_count: 0,
        medium_severity_count: 0,
        low_severity_count: 0,
        gaps_by