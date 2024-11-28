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
use aws_sdk_backup::Client as BackupClient;
use aws_sdk_glacier::Client as GlacierClient;
use aws_sdk_workspaces::Client as WorkspacesClient;
use aws_sdk_elasticache::Client as ElastiCacheClient;
use aws_sdk_docdb::Client as DocDBClient;
use aws_sdk_neptune::Client as NeptuneClient;
use clap::Parser;
use futures::{stream::FuturesUnordered, StreamExt};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error};

#[derive(Debug)]
pub enum AppError {
    AwsSdkError(String),
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    ConfigurationError(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::AwsSdkError(e) => write!(f, "AWS SDK error: {}", e),
            AppError::IoError(e) => write!(f, "IO error: {}", e),
            AppError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            AppError::ConfigurationError(e) => write!(f, "Configuration error: {}", e),
        }
    }
}

impl Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError::IoError(error)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        AppError::SerializationError(error)
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about = "AWS Encryption Gap Checker")]
struct Args {
    #[clap(short, long, default_value = "us-east-1")]
    region: String,

    #[clap(short, long)]
    profile: Option<String>,

    #[clap(short, long)]
    output: Option<PathBuf>,

    #[clap(short, long)]
    debug: bool,

    #[clap(long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EncryptionGap {
    service: String,
    resource_id: String,
    resource_name: Option<String>,
    issue: String,
    severity: String,
    recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_info: Option<String>,
    detection_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Summary {
    total_resources_scanned: usize,
    total_gaps_found: usize,
    gaps_by_severity: std::collections::HashMap<String, usize>,
    gaps_by_service: std::collections::HashMap<String, usize>,
    critical_issues: Vec<String>,
    scan_duration: f64,
    resources_by_service: std::collections::HashMap<String, usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanReport {
    timestamp: DateTime<Utc>,
    region: String,
    gaps: Vec<EncryptionGap>,
    summary: Summary,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    tool_version: String,
}

#[derive(Clone)]
struct ServiceChecker {
    name: String,
    region: String,
    progress_bar: Arc<ProgressBar>,
}

impl ServiceChecker {
    fn new(name: &str, region: &str, progress_bar: ProgressBar) -> Self {
        Self {
            name: name.to_string(),
            region: region.to_string(),
            progress_bar: Arc::new(progress_bar),
        }
    }

    fn update_progress(&self, msg: &str) {
        self.progress_bar.set_message(msg.to_string());
    }

    fn finish(&self) {
        self.progress_bar.finish_with_message("Complete");
    }
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
                service: "S3".to_string(),
                resource_id: bucket_name.to_string(),
                resource_name: Some(bucket_name.to_string()),
                issue: "No default encryption configured".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable S3 default encryption using KMS or AES-256".to_string(),
                additional_info: Some("Default encryption protects new objects automatically".to_string()),
                detection_time: Utc::now(),
            });
        }

        // Check versioning
        let versioning = client.get_bucket_versioning()
            .bucket(bucket_name)
            .send()
            .await?;

        if versioning.status().is_none() || versioning.status() != Some(&aws_sdk_s3::types::BucketVersioningStatus::Enabled) {
            gaps.push(EncryptionGap {
                service: "S3".to_string(),
                resource_id: bucket_name.to_string(),
                resource_name: Some(bucket_name.to_string()),
                issue: "Versioning not enabled".to_string(),
                severity: "MEDIUM".to_string(),
                recommendation: "Enable versioning for data protection".to_string(),
                additional_info: Some("Versioning helps protect against accidental deletion".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_dynamodb_encryption(client: &DynamoClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let tables = client.list_tables().send().await?;

    for table_name in tables.table_names().unwrap_or_default() {
        let table = client.describe_table()
            .table_name(table_name)
            .send()
            .await?;

        if let Some(table_desc) = table.table() {
            if table_desc.sse_description().is_none() {
                gaps.push(EncryptionGap {
                    service: "DynamoDB".to_string(),
                    resource_id: table_name.to_string(),
                    resource_name: Some(table_name.to_string()),
                    issue: "Server-side encryption not enabled".to_string(),
                    severity: "HIGH".to_string(),
                    recommendation: "Enable DynamoDB encryption using AWS KMS".to_string(),
                    additional_info: Some("Server-side encryption provides additional data protection".to_string()),
                    detection_time: Utc::now(),
                });
            }
        }
    }

    Ok(gaps)
}

async fn check_efs_encryption(client: &EfsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let fs_list = client.describe_file_systems().send().await?;

    for fs in fs_list.file_systems().unwrap_or_default() {
        if !fs.encrypted().unwrap_or_default() {
            gaps.push(EncryptionGap {
                service: "EFS".to_string(),
                resource_id: fs.file_system_id().unwrap_or_default().to_string(),
                resource_name: fs.name().map(String::from),
                issue: "EFS not encrypted".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable encryption for EFS file system".to_string(),
                additional_info: Some("Encryption cannot be enabled after creation".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_sns_encryption(client: &SnsClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let topics = client.list_topics().send().await?;

    for topic in topics.topics().unwrap_or_default() {
        let topic_arn = topic.topic_arn().unwrap_or_default();
        let attrs = client.get_topic_attributes()
            .topic_arn(topic_arn)
            .send()
            .await?;

        if !attrs.attributes().unwrap_or_default().contains_key("KmsMasterKeyId") {
            gaps.push(EncryptionGap {
                service: "SNS".to_string(),
                resource_id: topic_arn.to_string(),
                resource_name: None,
                issue: "SNS topic not encrypted with KMS".to_string(),
                severity: "MEDIUM".to_string(),
                recommendation: "Enable SNS topic encryption using KMS".to_string(),
                additional_info: Some("Message encryption provides additional security".to_string()),
                detection_time: Utc::now(),
            });
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
            .attribute_names("KmsMasterKeyId")
            .send()
            .await?;

        if !attrs.attributes().unwrap_or_default().contains_key("KmsMasterKeyId") {
            gaps.push(EncryptionGap {
                service: "SQS".to_string(),
                resource_id: queue_url.to_string(),
                resource_name: None,
                issue: "SQS queue not encrypted with KMS".to_string(),
                severity: "MEDIUM".to_string(),
                recommendation: "Enable SQS queue encryption using KMS".to_string(),
                additional_info: Some("Message encryption in transit and at rest".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_lambda_encryption(client: &LambdaClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let functions = client.list_functions().send().await?;

    for function in functions.functions().unwrap_or_default() {
        if function.kms_key_arn().is_none() {
            gaps.push(EncryptionGap {
                service: "Lambda".to_string(),
                resource_id: function.function_name().unwrap_or_default().to_string(),
                resource_name: Some(function.function_name().unwrap_or_default().to_string()),
                issue: "Lambda environment variables not encrypted with KMS".to_string(),
                severity: "MEDIUM".to_string(),
                recommendation: "Enable KMS encryption for environment variables".to_string(),
                additional_info: Some("KMS encryption protects sensitive configuration data".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_cloudtrail_encryption(client: &CloudTrailClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let trails = client.describe_trails().send().await?;

    for trail in trails.trail_list().unwrap_or_default() {
        if trail.kms_key_id().is_none() {
            gaps.push(EncryptionGap {
                service: "CloudTrail".to_string(),
                resource_id: trail.name().unwrap_or_default().to_string(),
                resource_name: Some(trail.name().unwrap_or_default().to_string()),
                issue: "CloudTrail logs not encrypted with KMS".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable KMS encryption for CloudTrail logs".to_string(),
                additional_info: Some("KMS encryption provides additional audit log protection".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_elasticsearch_encryption(client: &ElasticsearchClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let domains = client.list_domain_names().send().await?;

    for domain in domains.domain_names().unwrap_or_default() {
        let domain_status = client.describe_elasticsearch_domain()
            .domain_name(domain.domain_name().unwrap_or_default())
            .send()
            .await?;

        if let Some(config) = domain_status.domain_status().and_then(|s| s.encryption_at_rest_options()) {
            if !config.enabled().unwrap_or_default() {
                gaps.push(EncryptionGap {
                    service: "Elasticsearch".to_string(),
                    resource_id: domain.domain_name().unwrap_or_default().to_string(),
                    resource_name: Some(domain.domain_name().unwrap_or_default().to_string()),
                    issue: "Elasticsearch domain not encrypted".to_string(),
                    severity: "HIGH".to_string(),
                    recommendation: "Enable encryption at rest for Elasticsearch".to_string(),
                    additional_info: Some("Data encryption protects sensitive information".to_string()),
                    detection_time: Utc::now(),
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
        if !cluster.encrypted().unwrap_or_default() {
            gaps.push(EncryptionGap {
                service: "Redshift".to_string(),
                resource_id: cluster.cluster_identifier().unwrap_or_default().to_string(),
                resource_name: Some(cluster.cluster_identifier().unwrap_or_default().to_string()),
                issue: "Redshift cluster not encrypted".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable encryption for Redshift cluster".to_string(),
                additional_info: Some("Cluster encryption protects data at rest".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_docdb_encryption(client: &DocDBClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let clusters = client.describe_db_clusters().send().await?;

    for cluster in clusters.db_clusters().unwrap_or_default() {
        if !cluster.storage_encrypted().unwrap_or_default() {
            gaps.push(EncryptionGap {
                service: "DocumentDB".to_string(),
                resource_id: cluster.db_cluster_identifier().unwrap_or_default().to_string(),
                resource_name: Some(cluster.db_cluster_identifier().unwrap_or_default().to_string()),
                issue: "DocumentDB cluster not encrypted".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable storage encryption for DocumentDB cluster".to_string(),
                additional_info: Some("Storage encryption must be enabled during creation".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_neptune_encryption(client: &NeptuneClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let clusters = client.describe_db_clusters().send().await?;

    for cluster in clusters.db_clusters().unwrap_or_default() {
        if !cluster.storage_encrypted().unwrap_or_default() {
            gaps.push(EncryptionGap {
                service: "Neptune".to_string(),
                resource_id: cluster.db_cluster_identifier().unwrap_or_default().to_string(),
                resource_name: Some(cluster.db_cluster_identifier().unwrap_or_default().to_string()),
                issue: "Neptune cluster not encrypted".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable storage encryption for Neptune cluster".to_string(),
                additional_info: Some("Storage encryption must be enabled during creation".to_string()),
                detection_time: Utc::now(),
            });
        }
    }

    Ok(gaps)
}

async fn check_glacier_encryption(client: &GlacierClient, region: &str) -> Result<Vec<EncryptionGap>, Box<dyn Error>> {
    let mut gaps = Vec::new();
    let vaults = client.list_vaults().send().await?;

    for vault in vaults.vault_list().unwrap_or_default() {
        let vault_name = vault.vault_name().unwrap_or_default();
        
        let lock_config = client.get_vault_lock()
            .vault_name(vault_name)
            .send()
            .await;

        match lock_config {
            Ok(_) => {
                if !vault.locked().unwrap_or_default() {
                    gaps.push(EncryptionGap {
                        service: "Glacier".to_string(),
                        resource_id: vault_name.to_string(),
                        resource_name: Some(vault_name.to_string()),
                        issue: "Vault lock policy not enforced".to_string(),
                        severity: "MEDIUM".to_string(),
                        recommendation: "Enforce vault lock policy".to_string(),
                        additional_info: Some("Vault lock provides WORM protection".to_string()),
                        detection_time: Utc::now(),
                    });
                }
            },
            Err(_) => {
                gaps.push(EncryptionGap {
                    service: "Glacier".to_string(),
                    resource_id: vault_name.to_string(),
                    resource_name: Some(vault_name.to_string()),
                    issue: "No vault lock policy".to_string(),
                    severity: "MEDIUM".to_string(),
                    recommendation: "Configure and enforce vault lock policy".to_string(),
                    additional_info: Some("Vault lock ensures regulatory compliance".to_string()),
                    detection_time: Utc::now(),
                });
            }
        }
    }

    Ok(gaps)
}

async fn parallel_scan(config: &aws_config::SdkConfig) -> Result<Vec<EncryptionGap>, AppError> {
    let m = MultiProgress::new();
    let sty = ProgressStyle::default_spinner()
        .template("{spinner:.green} [{elapsed_precise}] {msg}")
        .unwrap();

    let region = config.region().unwrap().to_string();
    let mut futures = FuturesUnordered::new();
    
    let services = vec![
        ("S3", check_s3_encryption as fn(&S3Client, &str) -> _),
        ("DynamoDB", check_dynamodb_encryption as fn(&DynamoClient, &str) -> _),
        ("EFS", check_efs_encryption as fn(&EfsClient, &str) -> _),
        ("SNS", check_sns_encryption as fn(&SnsClient, &str) -> _),
        ("SQS", check_sqs_encryption as fn(&SqsClient, &str) -> _),
        ("Lambda", check_lambda_encryption as fn(&LambdaClient, &str) -> _),
        ("CloudTrail", check_cloudtrail_encryption as fn(&CloudTrailClient, &str) -> _),
        ("Elasticsearch", check_elasticsearch_encryption as fn(&ElasticsearchClient, &str) -> _),
        ("Redshift", check_redshift_encryption as fn(&RedshiftClient, &str) -> _),
        ("DocumentDB", check_docdb_encryption as fn(&DocDBClient, &str) -> _),
        ("Neptune", check_neptune_encryption as fn(&NeptuneClient, &str) -> _),
        ("Glacier", check_glacier_encryption as fn(&GlacierClient, &str) -> _),
    ];

    for (service_name, check_fn) in services {
        let pb = m.add(ProgressBar::new_spinner());
        pb.set_style(sty.clone());
        pb.set_message(format!("Scanning {}", service_name));
        
        let checker = ServiceChecker::new(service_name, &region, pb);
        let config = config.clone();
        let region = region.clone();

        futures.push(tokio::spawn(async move {
            let result = match service_name {
                "S3" => check_fn(&S3Client::new(&config), &region).await,
                "DynamoDB" => check_fn(&DynamoClient::new(&config), &region).await,
                "EFS" => check_fn(&EfsClient::new(&config), &region).await,
                "SNS" => check_fn(&SnsClient::new(&config), &region).await,
                "SQS" => check_fn(&SqsClient::new(&config), &region).await,
                "Lambda" => check_fn(&LambdaClient::new(&config), &region).await,
                "CloudTrail" => check_fn(&CloudTrailClient::new(&config), &region).await,
                "Elasticsearch" => check_fn(&ElasticsearchClient::new(&config), &region).await,
                "Redshift" => check_fn(&RedshiftClient::new(&config), &region).await,
                "DocumentDB" => check_fn(&DocDBClient::new(&config), &region).await,
                "Neptune" => check_fn(&NeptuneClient::new(&config), &region).await,
                "Glacier" => check_fn(&GlacierClient::new(&config), &region).await,
                _ => unreachable!(),
            };

            checker.progress_bar.set_position(100);
            checker.finish();
            result
        }));
    }

    let mut all_gaps = Vec::new();
    while let Some(result) = futures.next().await {
        match result {
            Ok(Ok(gaps)) => {
                all_gaps.extend(gaps);
            }
            Ok(Err(e)) => {
                error!("Error scanning service: {}", e);
            }
            Err(e) => {
                error!("Task error: {}", e);
            }
        }
    }

    Ok(all_gaps)
}

fn generate_summary(gaps: &[EncryptionGap]) -> Summary {
    let scan_start_time = Utc::now();
    let mut gaps_by_severity = std::collections::HashMap::new();
    let mut gaps_by_service = std::collections::HashMap::new();
    let mut resources_by_service = std::collections::HashMap::new();
    let mut critical_issues = Vec::new();

    for gap in gaps {
        *gaps_by_severity.entry(gap.severity.clone()).or_insert(0) += 1;
        *gaps_by_service.entry(gap.service.clone()).or_insert(0) += 1;
        *resources_by_service.entry(gap.service.clone()).or_insert(0) += 1;

        if gap.severity == "HIGH" {
            critical_issues.push(format!("{}: {}", gap.resource_id, gap.issue));
        }
    }

    let scan_duration = (Utc::now() - scan_start_time).num_seconds() as f64;

    Summary {
        total_resources_scanned: resources_by_service.values().sum(),
        total_gaps_found: gaps.len(),
        gaps_by_severity,
        gaps_by_service,
        critical_issues,
        scan_duration,
        resources_by_service,
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let args = Args::parse();

    // Set up logging
    let log_level = if args.debug {
        tracing::Level::DEBUG
    } else if args.verbose {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting AWS Encryption Gap Checker");
    info!("Region: {}", args.region);
    
    // Load AWS configuration
    let config = aws_config::from_env()
        .region(aws_sdk_s3::Region::new(args.region.clone()))
        .profile_name(args.profile.clone())
        .load()
        .await;

    info!("Scanning AWS services for encryption gaps...");
    let scan_start = Utc::now();
    let gaps = parallel_scan(&config).await?;
    
    let summary = generate_summary(&gaps);
    let report = ScanReport {
        timestamp: Utc::now(),
        region: args.region.clone(),
        gaps,
        summary,
        account_id: None, // TODO: Add AWS account ID fetching
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    if let Some(output_path) = args.output {
        info!("Saving report to {}", output_path.display());
        let file = File::create(&output_path).map_err(|e| {
            AppError::IoError(e)
        })?;
        serde_json::to_writer_pretty(file, &report)?;
        info!("Report saved successfully");
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    info!("Scan completed in {} seconds", (Utc::now() - scan_start).num_seconds());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_summary() {
        let gaps = vec![
            EncryptionGap {
                service: "S3".to_string(),
                resource_id: "bucket1".to_string(),
                resource_name: Some("bucket1".to_string()),
                issue: "No encryption".to_string(),
                severity: "HIGH".to_string(),
                recommendation: "Enable encryption".to_string(),
                additional_info: None,
                detection_time: Utc::now(),
            },
            EncryptionGap {
                service: "S3".to_string(),
                resource_id: "bucket2".to_string(),
                resource_name: Some("bucket2".to_string()),
                issue: "No encryption".to_string(),
                severity: "MEDIUM".to_string(),
                recommendation: "Enable encryption".to_string(),
                additional_info: None,
                detection_time: Utc::now(),
            },
        ];

        let summary = generate_summary(&gaps);
        assert_eq!(summary.total_gaps_found, 2);
        assert_eq!(summary.gaps_by_service.get("S3").unwrap(), &2);
        assert_eq!(summary.gaps_by_severity.get("HIGH").unwrap(), &1);
        assert_eq!(summary.gaps_by_severity.get("MEDIUM").unwrap(), &1);
        assert_eq!(summary.critical_issues.len(), 1);
    }
}