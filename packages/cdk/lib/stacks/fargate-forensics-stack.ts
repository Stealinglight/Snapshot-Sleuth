/**
 * Fargate Forensics Stack
 *
 * Creates ECS infrastructure for running forensic tool containers:
 * - ECS Cluster
 * - Task definitions for each tool
 * - ECR repositories
 * - IAM roles with least privilege
 */
import * as cdk from 'aws-cdk-lib';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

/**
 * Resource allocation configuration for forensic tools
 */
export interface ToolResourceConfig {
  /** Base CPU units (1024 = 1 vCPU) */
  baseCpu: number;
  /** Base memory in MB */
  baseMemoryMb: number;
  /** Additional CPU per 100GB of snapshot */
  cpuPer100Gb: number;
  /** Additional memory per 100GB of snapshot */
  memoryPer100Gb: number;
  /** Maximum CPU units */
  maxCpu: number;
  /** Maximum memory in MB */
  maxMemoryMb: number;
  /** Base timeout in minutes */
  baseTimeoutMinutes: number;
  /** Additional timeout per GB */
  timeoutPerGbMinutes: number;
  /** Maximum timeout in minutes */
  maxTimeoutMinutes: number;
  /** Whether tool failure should abort workflow */
  critical: boolean;
}

/**
 * Default resource configurations per tool
 * Based on the design document's resource allocation matrix
 */
export const DEFAULT_TOOL_CONFIGS: Record<string, ToolResourceConfig> = {
  'yara': {
    baseCpu: 1024,           // 1 vCPU
    baseMemoryMb: 4096,      // 4 GB
    cpuPer100Gb: 512,        // +0.5 vCPU
    memoryPer100Gb: 2048,    // +2 GB
    maxCpu: 4096,            // 4 vCPU
    maxMemoryMb: 16384,      // 16 GB
    baseTimeoutMinutes: 10,
    timeoutPerGbMinutes: 0.5,
    maxTimeoutMinutes: 60,
    critical: true,
  },
  'clamav': {
    baseCpu: 2048,           // 2 vCPU
    baseMemoryMb: 4096,      // 4 GB
    cpuPer100Gb: 512,        // +0.5 vCPU
    memoryPer100Gb: 2048,    // +2 GB
    maxCpu: 4096,            // 4 vCPU
    maxMemoryMb: 16384,      // 16 GB
    baseTimeoutMinutes: 15,
    timeoutPerGbMinutes: 1,
    maxTimeoutMinutes: 120,
    critical: false,         // Optional tool
  },
  'evidence-miner': {
    baseCpu: 2048,           // 2 vCPU
    baseMemoryMb: 8192,      // 8 GB
    cpuPer100Gb: 1024,       // +1 vCPU
    memoryPer100Gb: 4096,    // +4 GB
    maxCpu: 8192,            // 8 vCPU
    maxMemoryMb: 32768,      // 32 GB
    baseTimeoutMinutes: 20,
    timeoutPerGbMinutes: 1,
    maxTimeoutMinutes: 120,
    critical: true,
  },
  'log2timeline': {
    baseCpu: 4096,           // 4 vCPU
    baseMemoryMb: 16384,     // 16 GB
    cpuPer100Gb: 2048,       // +2 vCPU
    memoryPer100Gb: 8192,    // +8 GB
    maxCpu: 16384,           // 16 vCPU
    maxMemoryMb: 65536,      // 64 GB
    baseTimeoutMinutes: 30,
    timeoutPerGbMinutes: 2,
    maxTimeoutMinutes: 240,
    critical: true,
  },
};

export interface FargateForensicsStackProps extends cdk.StackProps {
  /** Project name for resource naming */
  projectName?: string;
  /** Environment name */
  environment?: string;
  /** VPC for Fargate tasks */
  vpc: ec2.IVpc;
  /** Security group for Fargate tasks */
  securityGroup: ec2.ISecurityGroup;
  /** Private subnets for tasks */
  subnets: ec2.ISubnet[];
  /** Evidence bucket for results */
  evidenceBucket: s3.IBucket;
  /** Signatures bucket for rules/definitions */
  signaturesBucket: s3.IBucket;
  /** KMS key for encryption (optional) */
  kmsKey?: kms.IKey;
  /** Custom tool configurations (optional) */
  toolConfigs?: Record<string, Partial<ToolResourceConfig>>;
}

export class FargateForensicsStack extends cdk.Stack {
  /** ECS Cluster for forensic tasks */
  public readonly cluster: ecs.Cluster;

  /** ECR repositories for each tool */
  public readonly repositories: Record<string, ecr.Repository>;

  /** Task definitions for each tool */
  public readonly taskDefinitions: Record<string, ecs.FargateTaskDefinition>;

  /** Task execution role (shared) */
  public readonly executionRole: iam.Role;

  /** Log group for container logs */
  public readonly logGroup: logs.LogGroup;

  private readonly projectName: string;
  private readonly envName: string;
  private readonly toolConfigs: Record<string, ToolResourceConfig>;

  constructor(scope: Construct, id: string, props: FargateForensicsStackProps) {
    super(scope, id, props);

    this.projectName = props.projectName ?? this.node.tryGetContext('projectName') ?? 'snapshot-sleuth';
    this.envName = props.environment ?? this.node.tryGetContext('environment') ?? 'development';

    // Merge custom configs with defaults
    this.toolConfigs = { ...DEFAULT_TOOL_CONFIGS };
    if (props.toolConfigs) {
      for (const [tool, config] of Object.entries(props.toolConfigs)) {
        this.toolConfigs[tool] = { ...this.toolConfigs[tool], ...config };
      }
    }

    // Create log group
    this.logGroup = new logs.LogGroup(this, 'ForensicsLogGroup', {
      logGroupName: `/aws/ecs/${this.projectName}-forensics-${this.envName}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Create ECS cluster
    this.cluster = new ecs.Cluster(this, 'ForensicsCluster', {
      clusterName: `${this.projectName}-forensics-${this.envName}`,
      vpc: props.vpc,
      containerInsights: true,
    });

    // Create shared execution role
    this.executionRole = this.createExecutionRole();

    // Create ECR repositories
    this.repositories = this.createRepositories();

    // Create task definitions
    this.taskDefinitions = this.createTaskDefinitions(
      props.evidenceBucket,
      props.signaturesBucket,
      props.kmsKey
    );

    // Outputs
    new cdk.CfnOutput(this, 'ClusterArn', {
      value: this.cluster.clusterArn,
      description: 'Forensics ECS Cluster ARN',
      exportName: `${this.projectName}-${this.envName}-cluster-arn`,
    });

    for (const [tool, repo] of Object.entries(this.repositories)) {
      new cdk.CfnOutput(this, `${tool}RepoUri`, {
        value: repo.repositoryUri,
        description: `ECR repository URI for ${tool}`,
      });
    }
  }

  /**
   * Create the shared task execution role
   */
  private createExecutionRole(): iam.Role {
    const role = new iam.Role(this, 'ExecutionRole', {
      roleName: `${this.projectName}-${this.envName}-ecs-execution`,
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'ECS task execution role for forensic containers',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    // Add ECR pull permissions
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'ECRPull',
      effect: iam.Effect.ALLOW,
      actions: [
        'ecr:GetAuthorizationToken',
        'ecr:BatchCheckLayerAvailability',
        'ecr:GetDownloadUrlForLayer',
        'ecr:BatchGetImage',
      ],
      resources: ['*'],
    }));

    return role;
  }

  /**
   * Create ECR repositories for each tool
   */
  private createRepositories(): Record<string, ecr.Repository> {
    const tools = ['forensics-base', 'yara', 'clamav', 'evidence-miner', 'log2timeline'];
    const repositories: Record<string, ecr.Repository> = {};

    for (const tool of tools) {
      repositories[tool] = new ecr.Repository(this, `${tool}Repo`, {
        repositoryName: `${this.projectName}/${tool}`,
        imageScanOnPush: true,
        imageTagMutability: ecr.TagMutability.MUTABLE,
        lifecycleRules: [
          {
            description: 'Keep only last 10 images',
            maxImageCount: 10,
            rulePriority: 1,
          },
        ],
        removalPolicy: cdk.RemovalPolicy.DESTROY,
        emptyOnDelete: true,
      });
    }

    return repositories;
  }

  /**
   * Create task definitions for each forensic tool
   */
  private createTaskDefinitions(
    evidenceBucket: s3.IBucket,
    signaturesBucket: s3.IBucket,
    kmsKey?: kms.IKey
  ): Record<string, ecs.FargateTaskDefinition> {
    const taskDefinitions: Record<string, ecs.FargateTaskDefinition> = {};
    const tools = ['yara', 'clamav', 'evidence-miner', 'log2timeline'];

    for (const tool of tools) {
      const config = this.toolConfigs[tool];
      const taskRole = this.createTaskRole(tool, evidenceBucket, signaturesBucket, kmsKey);

      const taskDef = new ecs.FargateTaskDefinition(this, `${tool}TaskDef`, {
        family: `${this.projectName}-${tool}-${this.envName}`,
        cpu: config.baseCpu,
        memoryLimitMiB: config.baseMemoryMb,
        executionRole: this.executionRole,
        taskRole,
        // Enable EFS/EBS volume mounting
        volumes: [
          {
            name: 'evidence',
            // EBS volume will be configured at runtime via Step Functions
          },
        ],
      });

      // Add container definition
      const container = taskDef.addContainer(`${tool}Container`, {
        containerName: tool,
        image: ecs.ContainerImage.fromEcrRepository(
          this.repositories[tool],
          'latest'
        ),
        logging: ecs.LogDrivers.awsLogs({
          streamPrefix: tool,
          logGroup: this.logGroup,
        }),
        environment: {
          TOOL_NAME: tool,
          AWS_REGION: this.region,
          EVIDENCE_BUCKET: evidenceBucket.bucketName,
          SIGNATURE_BUCKET: signaturesBucket.bucketName,
          SIGNATURE_PREFIX: 'signatures/',
          MOUNT_PATH: '/mnt/evidence',
          OUTPUT_PATH: '/output',
          HEARTBEAT_INTERVAL_SECONDS: '30',
        },
        // Health check
        healthCheck: {
          command: ['CMD-SHELL', 'test -f /app/entrypoint.py || exit 1'],
          interval: cdk.Duration.seconds(30),
          timeout: cdk.Duration.seconds(5),
          retries: 3,
          startPeriod: cdk.Duration.seconds(60),
        },
      });

      // Mount evidence volume
      container.addMountPoints({
        sourceVolume: 'evidence',
        containerPath: '/mnt/evidence',
        readOnly: true,
      });

      taskDefinitions[tool] = taskDef;
    }

    return taskDefinitions;
  }

  /**
   * Create task role with least privilege for a specific tool
   */
  private createTaskRole(
    tool: string,
    evidenceBucket: s3.IBucket,
    signaturesBucket: s3.IBucket,
    kmsKey?: kms.IKey
  ): iam.Role {
    const role = new iam.Role(this, `${tool}TaskRole`, {
      roleName: `${this.projectName}-${this.envName}-${tool}-task`,
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: `Task role for ${tool} forensic container`,
    });

    // S3: Write to evidence bucket
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EvidenceBucketWrite',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:PutObject',
        's3:PutObjectAcl',
      ],
      resources: [`${evidenceBucket.bucketArn}/*`],
    }));

    // S3: Read from signatures bucket
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'SignatureBucketRead',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:ListBucket',
      ],
      resources: [
        signaturesBucket.bucketArn,
        `${signaturesBucket.bucketArn}/*`,
      ],
    }));

    // CloudWatch Logs
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CloudWatchLogs',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogStream',
        'logs:PutLogEvents',
      ],
      resources: [this.logGroup.logGroupArn],
    }));

    // EventBridge: Emit heartbeats
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EventBridgeHeartbeat',
      effect: iam.Effect.ALLOW,
      actions: ['events:PutEvents'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'events:source': 'snapshot-sleuth.forensics',
        },
      },
    }));

    // EBS: Describe volumes (for volume info)
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EBSDescribe',
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeVolumes',
        'ec2:DescribeSnapshots',
      ],
      resources: ['*'],
    }));

    // KMS: Decrypt if using customer-managed key
    if (kmsKey) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'KMSDecrypt',
        effect: iam.Effect.ALLOW,
        actions: [
          'kms:Decrypt',
          'kms:GenerateDataKey',
        ],
        resources: [kmsKey.keyArn],
      }));
    }

    return role;
  }

  /**
   * Calculate resource allocation for a tool based on snapshot size
   */
  public static calculateResources(
    tool: string,
    snapshotSizeGb: number,
    configs: Record<string, ToolResourceConfig> = DEFAULT_TOOL_CONFIGS
  ): { cpu: number; memoryMb: number; timeoutMinutes: number } {
    const config = configs[tool];
    if (!config) {
      throw new Error(`Unknown tool: ${tool}`);
    }

    const scaleFactor = snapshotSizeGb / 100;

    const cpu = Math.min(
      config.baseCpu + Math.floor(config.cpuPer100Gb * scaleFactor),
      config.maxCpu
    );

    const memoryMb = Math.min(
      config.baseMemoryMb + Math.floor(config.memoryPer100Gb * scaleFactor),
      config.maxMemoryMb
    );

    const timeoutMinutes = Math.min(
      config.baseTimeoutMinutes + Math.floor(config.timeoutPerGbMinutes * snapshotSizeGb),
      config.maxTimeoutMinutes
    );

    return { cpu, memoryMb, timeoutMinutes };
  }

  /**
   * Get tool criticality (whether failure should abort workflow)
   */
  public static isToolCritical(
    tool: string,
    configs: Record<string, ToolResourceConfig> = DEFAULT_TOOL_CONFIGS
  ): boolean {
    return configs[tool]?.critical ?? true;
  }
}
