/**
 * Forensics VPC Stack
 *
 * Creates a private VPC with VPC endpoints for Fargate forensic tasks.
 * No NAT gateway - all traffic stays within AWS network via endpoints.
 */
import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface ForensicsVpcStackProps extends cdk.StackProps {
  /**
   * Project name for resource naming
   */
  projectName?: string;

  /**
   * Environment name (development, staging, production)
   */
  environment?: string;

  /**
   * CIDR block for the VPC
   * @default '10.0.0.0/16'
   */
  vpcCidr?: string;

  /**
   * Number of availability zones to use
   * @default 2
   */
  maxAzs?: number;
}

export class ForensicsVpcStack extends cdk.Stack {
  /**
   * The VPC for Fargate forensic tasks
   */
  public readonly vpc: ec2.Vpc;

  /**
   * Security group for Fargate forensic tasks
   */
  public readonly forensicsSecurityGroup: ec2.SecurityGroup;

  /**
   * Security group for VPC endpoints
   */
  public readonly endpointSecurityGroup: ec2.SecurityGroup;

  /**
   * Private subnets for Fargate tasks
   */
  public readonly privateSubnets: ec2.ISubnet[];

  constructor(scope: Construct, id: string, props: ForensicsVpcStackProps = {}) {
    super(scope, id, props);

    const projectName = props.projectName ?? this.node.tryGetContext('projectName') ?? 'snapshot-sleuth';
    const environment = props.environment ?? this.node.tryGetContext('environment') ?? 'development';
    const vpcCidr = props.vpcCidr ?? '10.0.0.0/16';
    const maxAzs = props.maxAzs ?? 2;

    // Create VPC with private subnets only (no NAT gateway)
    this.vpc = new ec2.Vpc(this, 'ForensicsVpc', {
      vpcName: `${projectName}-forensics-${environment}`,
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs,
      // Only private subnets - no internet access
      subnetConfiguration: [
        {
          name: 'forensics-private',
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
      // No NAT gateway - fully isolated
      natGateways: 0,
      // Enable DNS support for VPC endpoints
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    this.privateSubnets = this.vpc.isolatedSubnets;

    // Security group for VPC endpoints
    this.endpointSecurityGroup = new ec2.SecurityGroup(this, 'EndpointSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: `${projectName}-endpoints-${environment}`,
      description: 'Security group for VPC endpoints',
      allowAllOutbound: false,
    });

    // Security group for Fargate forensic tasks
    this.forensicsSecurityGroup = new ec2.SecurityGroup(this, 'ForensicsSecurityGroup', {
      vpc: this.vpc,
      securityGroupName: `${projectName}-forensics-${environment}`,
      description: 'Security group for Fargate forensic tasks',
      allowAllOutbound: false,
    });

    // Allow Fargate tasks to communicate with VPC endpoints (HTTPS)
    this.endpointSecurityGroup.addIngressRule(
      this.forensicsSecurityGroup,
      ec2.Port.tcp(443),
      'Allow HTTPS from Fargate tasks'
    );

    // Allow Fargate tasks to reach VPC endpoints
    this.forensicsSecurityGroup.addEgressRule(
      this.endpointSecurityGroup,
      ec2.Port.tcp(443),
      'Allow HTTPS to VPC endpoints'
    );

    // Create VPC endpoints for AWS services needed by Fargate tasks
    this.createVpcEndpoints(projectName, environment);

    // Add flow logs for security monitoring
    this.vpc.addFlowLog('FlowLog', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    // Tags
    cdk.Tags.of(this.vpc).add('Project', projectName);
    cdk.Tags.of(this.vpc).add('Environment', environment);
    cdk.Tags.of(this.vpc).add('Purpose', 'Forensics');

    // Outputs
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      description: 'Forensics VPC ID',
      exportName: `${projectName}-${environment}-vpc-id`,
    });

    new cdk.CfnOutput(this, 'ForensicsSecurityGroupId', {
      value: this.forensicsSecurityGroup.securityGroupId,
      description: 'Forensics security group ID',
      exportName: `${projectName}-${environment}-forensics-sg-id`,
    });

    new cdk.CfnOutput(this, 'PrivateSubnetIds', {
      value: this.privateSubnets.map(s => s.subnetId).join(','),
      description: 'Private subnet IDs for Fargate tasks',
      exportName: `${projectName}-${environment}-private-subnet-ids`,
    });
  }

  /**
   * Create VPC endpoints for all required AWS services
   */
  private createVpcEndpoints(_projectName: string, _environment: string): void {
    // Interface endpoints (use PrivateLink)
    const interfaceEndpoints: Array<{
      service: ec2.InterfaceVpcEndpointAwsService;
      name: string;
    }> = [
      // ECR endpoints for pulling container images
      { service: ec2.InterfaceVpcEndpointAwsService.ECR, name: 'ecr-api' },
      { service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER, name: 'ecr-dkr' },

      // CloudWatch Logs for container logging
      { service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS, name: 'logs' },

      // EventBridge for heartbeat emission
      { service: ec2.InterfaceVpcEndpointAwsService.EVENTBRIDGE, name: 'events' },

      // STS for IAM credential fetching
      { service: ec2.InterfaceVpcEndpointAwsService.STS, name: 'sts' },

      // EBS Direct API for volume operations
      { service: ec2.InterfaceVpcEndpointAwsService.EBS_DIRECT, name: 'ebs-direct' },

      // EC2 for EBS volume attachment operations
      { service: ec2.InterfaceVpcEndpointAwsService.EC2, name: 'ec2' },

      // Secrets Manager (optional - for future credential storage)
      { service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER, name: 'secretsmanager' },

      // KMS for encryption operations
      { service: ec2.InterfaceVpcEndpointAwsService.KMS, name: 'kms' },

      // Step Functions for task tokens (if using callback pattern)
      { service: ec2.InterfaceVpcEndpointAwsService.STEP_FUNCTIONS, name: 'states' },
    ];

    for (const endpoint of interfaceEndpoints) {
      new ec2.InterfaceVpcEndpoint(this, `Endpoint-${endpoint.name}`, {
        vpc: this.vpc,
        service: endpoint.service,
        securityGroups: [this.endpointSecurityGroup],
        subnets: { subnets: this.privateSubnets },
        privateDnsEnabled: true,
      });
    }

    // Gateway endpoints (free, no PrivateLink charges)
    // S3 Gateway endpoint for evidence bucket and signature access
    new ec2.GatewayVpcEndpoint(this, 'Endpoint-s3', {
      vpc: this.vpc,
      service: ec2.GatewayVpcEndpointAwsService.S3,
      subnets: [{ subnets: this.privateSubnets }],
    });

    // DynamoDB Gateway endpoint (if needed for future state tracking)
    new ec2.GatewayVpcEndpoint(this, 'Endpoint-dynamodb', {
      vpc: this.vpc,
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
      subnets: [{ subnets: this.privateSubnets }],
    });
  }

  /**
   * Create IAM role for Fargate forensic tasks with least privilege
   */
  public createForensicsTaskRole(
    id: string,
    toolName: string,
    evidenceBucketArn: string,
    signatureBucketArn: string,
    kmsKeyArn?: string
  ): iam.Role {
    const role = new iam.Role(this, id, {
      roleName: `${this.node.tryGetContext('projectName') ?? 'snapshot-sleuth'}-${toolName}-task-role`,
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: `Task role for ${toolName} Fargate forensic task`,
    });

    // S3 permissions for evidence bucket (write results)
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EvidenceBucketWrite',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:PutObject',
        's3:PutObjectAcl',
      ],
      resources: [`${evidenceBucketArn}/*`],
    }));

    // S3 permissions for signature bucket (read signatures)
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'SignatureBucketRead',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:ListBucket',
      ],
      resources: [
        signatureBucketArn,
        `${signatureBucketArn}/*`,
      ],
    }));

    // CloudWatch Logs permissions
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'CloudWatchLogs',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogStream',
        'logs:PutLogEvents',
      ],
      resources: ['*'],
    }));

    // EventBridge permissions for heartbeat
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EventBridgeHeartbeat',
      effect: iam.Effect.ALLOW,
      actions: [
        'events:PutEvents',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'events:source': 'snapshot-sleuth.forensics',
        },
      },
    }));

    // EBS permissions for volume access (read-only)
    role.addToPolicy(new iam.PolicyStatement({
      sid: 'EBSReadOnly',
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeVolumes',
        'ec2:DescribeSnapshots',
      ],
      resources: ['*'],
    }));

    // KMS permissions if using customer-managed key
    if (kmsKeyArn) {
      role.addToPolicy(new iam.PolicyStatement({
        sid: 'KMSDecrypt',
        effect: iam.Effect.ALLOW,
        actions: [
          'kms:Decrypt',
          'kms:GenerateDataKey',
        ],
        resources: [kmsKeyArn],
      }));
    }

    return role;
  }

  /**
   * Create ECS task execution role with permissions to pull images and write logs
   */
  public createTaskExecutionRole(id: string): iam.Role {
    const role = new iam.Role(this, id, {
      roleName: `${this.node.tryGetContext('projectName') ?? 'snapshot-sleuth'}-task-execution-role`,
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Task execution role for Fargate forensic tasks',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    return role;
  }
}
