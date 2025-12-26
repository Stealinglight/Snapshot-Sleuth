/**
 * Storage construct for S3 buckets
 */
import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

export interface StorageConstructProps {
  bucketPrefix: string;
  environment: string;
  kmsKey?: kms.IKey;
}

export class StorageConstruct extends Construct {
  public readonly evidenceBucket: s3.Bucket;
  public readonly artifactsBucket: s3.Bucket;
  public readonly logsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: StorageConstructProps) {
    super(scope, id);

    // Evidence bucket - stores forensic evidence
    this.evidenceBucket = new s3.Bucket(this, 'EvidenceBucket', {
      bucketName: `${props.bucketPrefix}-evidence-${props.environment}`,
      encryption: props.kmsKey
        ? s3.BucketEncryption.KMS
        : s3.BucketEncryption.S3_MANAGED,
      encryptionKey: props.kmsKey,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          transitions: [
            {
              storageClass: s3.StorageClass.INTELLIGENT_TIERING,
              transitionAfter: cdk.Duration.days(30),
            },
          ],
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Artifacts bucket - stores tool outputs
    this.artifactsBucket = new s3.Bucket(this, 'ArtifactsBucket', {
      bucketName: `${props.bucketPrefix}-artifacts-${props.environment}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          transitions: [
            {
              storageClass: s3.StorageClass.GLACIER,
              transitionAfter: cdk.Duration.days(90),
            },
          ],
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Logs bucket - stores CloudTrail and application logs
    this.logsBucket = new s3.Bucket(this, 'LogsBucket', {
      bucketName: `${props.bucketPrefix}-logs-${props.environment}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          expiration: cdk.Duration.days(90),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add tags
    cdk.Tags.of(this.evidenceBucket).add('Purpose', 'Evidence Storage');
    cdk.Tags.of(this.artifactsBucket).add('Purpose', 'Artifacts Storage');
    cdk.Tags.of(this.logsBucket).add('Purpose', 'Logs Storage');
  }
}
