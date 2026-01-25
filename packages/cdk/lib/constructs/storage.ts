/**
 * Storage construct for S3 buckets
 */
import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
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
  public readonly signaturesBucket: s3.Bucket;

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

    // Signatures bucket - stores YARA rules and ClamAV definitions
    // Structure:
    //   signatures/
    //   ├── yara/
    //   │   ├── rules/           # Custom YARA rules
    //   │   │   └── *.yar
    //   │   └── compiled/        # Pre-compiled rules (optional)
    //   │       └── *.yarc
    //   ├── clamav/
    //   │   ├── main.cvd         # ClamAV main database
    //   │   ├── daily.cld        # ClamAV daily updates
    //   │   └── bytecode.cld     # ClamAV bytecode signatures
    //   └── custom/
    //       └── indicators.json  # Custom indicators of compromise
    this.signaturesBucket = new s3.Bucket(this, 'SignaturesBucket', {
      bucketName: `${props.bucketPrefix}-signatures-${props.environment}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true, // Keep signature version history
      lifecycleRules: [
        {
          // Keep old versions for 30 days (rollback capability)
          noncurrentVersionExpiration: cdk.Duration.days(30),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      // Enable CORS for signature upload tools
      cors: [
        {
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.PUT],
          allowedOrigins: ['*'], // Restrict in production
          allowedHeaders: ['*'],
        },
      ],
    });

    // Add tags
    cdk.Tags.of(this.evidenceBucket).add('Purpose', 'Evidence Storage');
    cdk.Tags.of(this.artifactsBucket).add('Purpose', 'Artifacts Storage');
    cdk.Tags.of(this.logsBucket).add('Purpose', 'Logs Storage');
    cdk.Tags.of(this.signaturesBucket).add('Purpose', 'Signature Storage');
  }

  /**
   * Grant read access to signatures for a Fargate task role
   */
  public grantSignatureRead(grantee: iam.IGrantable): void {
    this.signaturesBucket.grantRead(grantee);
  }

  /**
   * Grant write access to evidence bucket for a Fargate task role
   */
  public grantEvidenceWrite(grantee: iam.IGrantable): void {
    this.evidenceBucket.grantWrite(grantee);
  }

  /**
   * Get the S3 URI for YARA rules
   */
  public get yaraRulesUri(): string {
    return `s3://${this.signaturesBucket.bucketName}/signatures/yara/rules/`;
  }

  /**
   * Get the S3 URI for ClamAV definitions
   */
  public get clamavDefinitionsUri(): string {
    return `s3://${this.signaturesBucket.bucketName}/signatures/clamav/`;
  }

  /**
   * Get the S3 URI for custom indicators
   */
  public get customIndicatorsUri(): string {
    return `s3://${this.signaturesBucket.bucketName}/signatures/custom/`;
  }
}
