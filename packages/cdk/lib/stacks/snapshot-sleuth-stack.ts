/**
 * Main Snapshot Sleuth stack
 *
 * Orchestrates the forensic analysis workflow using Step Functions
 * with Fargate tasks for each forensic tool.
 */
import * as cdk from 'aws-cdk-lib';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import { Construct } from 'constructs';
import { StorageConstruct, MonitoringConstruct } from '../constructs';
import { FargateForensicsStack, DEFAULT_TOOL_CONFIGS } from './fargate-forensics-stack';
import { ForensicsVpcStack } from './forensics-vpc-stack';

export interface SnapshotSleuthStackProps extends cdk.StackProps {
  /**
   * Optional: Existing VPC stack to use
   * If not provided, creates a new one
   */
  vpcStack?: ForensicsVpcStack;

  /**
   * Optional: Existing Fargate stack to use
   * If not provided, creates a new one
   */
  fargateStack?: FargateForensicsStack;
}

export class SnapshotSleuthStack extends cdk.Stack {
  public readonly stateMachine: stepfunctions.StateMachine;
  public readonly storage: StorageConstruct;
  public readonly monitoring: MonitoringConstruct;

  constructor(scope: Construct, id: string, props?: SnapshotSleuthStackProps) {
    super(scope, id, props);

    const environment = this.node.tryGetContext('environment') || 'development';
    const projectName = this.node.tryGetContext('projectName') || 'snapshot-sleuth';

    // Create KMS key for encryption
    const encryptionKey = new kms.Key(this, 'EncryptionKey', {
      description: `${projectName} encryption key`,
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Create storage resources
    this.storage = new StorageConstruct(this, 'Storage', {
      bucketPrefix: projectName,
      environment,
      kmsKey: encryptionKey,
    });

    // Create monitoring resources
    this.monitoring = new MonitoringConstruct(this, 'Monitoring', {
      projectName,
      environment,
      alarmEmail: this.node.tryGetContext('alarmEmail'),
    });

    // Enable CloudTrail
    new cloudtrail.Trail(this, 'AuditTrail', {
      trailName: `${projectName}-${environment}`,
      bucket: this.storage.logsBucket,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      managementEvents: cloudtrail.ReadWriteType.ALL,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: this.monitoring.logGroup,
    });

    // Create or use VPC stack
    const vpcStack = props?.vpcStack ?? new ForensicsVpcStack(this, 'VpcStack', {
      projectName,
      environment,
    });

    // Create or use Fargate stack
    const fargateStack = props?.fargateStack ?? new FargateForensicsStack(this, 'FargateStack', {
      projectName,
      environment,
      vpc: vpcStack.vpc,
      securityGroup: vpcStack.forensicsSecurityGroup,
      subnets: vpcStack.privateSubnets,
      evidenceBucket: this.storage.evidenceBucket,
      signaturesBucket: this.storage.signaturesBucket,
      kmsKey: encryptionKey,
    });

    // Create Lambda functions
    const lambdaFunctions = this.createLambdaFunctions(projectName, environment, encryptionKey);

    // Create Step Functions state machine
    this.stateMachine = this.createWorkflowStateMachine(
      projectName,
      environment,
      this.storage,
      this.monitoring,
      fargateStack,
      vpcStack,
      lambdaFunctions
    );

    // Add workflow metrics to dashboard
    this.monitoring.addWorkflowMetrics(this.stateMachine.stateMachineArn);

    // Outputs
    new cdk.CfnOutput(this, 'StateMachineArn', {
      value: this.stateMachine.stateMachineArn,
      description: 'Forensic workflow state machine ARN',
    });

    new cdk.CfnOutput(this, 'EvidenceBucketName', {
      value: this.storage.evidenceBucket.bucketName,
      description: 'Evidence storage bucket name',
    });

    new cdk.CfnOutput(this, 'SignaturesBucketName', {
      value: this.storage.signaturesBucket.bucketName,
      description: 'Signatures storage bucket name',
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.monitoring.dashboard.dashboardName}`,
      description: 'CloudWatch dashboard URL',
    });
  }

  /**
   * Create Lambda functions for workflow steps
   */
  private createLambdaFunctions(
    projectName: string,
    environment: string,
    kmsKey: kms.Key
  ): {
    validateSnapshot: lambda.Function;
    aggregateResults: lambda.Function;
    sendNotification: lambda.Function;
    createVolume: lambda.Function;
    deleteVolume: lambda.Function;
  } {
    // Common Lambda configuration
    const commonProps = {
      runtime: lambda.Runtime.NODEJS_18_X,
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        NODE_OPTIONS: '--enable-source-maps',
        REGION: this.region,
      },
    };

    // Validate Snapshot Lambda
    const validateSnapshot = new lambdaNode.NodejsFunction(this, 'ValidateSnapshotFn', {
      ...commonProps,
      functionName: `${projectName}-${environment}-validate-snapshot`,
      entry: require.resolve('@snapshot-sleuth/lambda-ts/src/handlers/validate-snapshot'),
      description: 'Validates that a snapshot exists and is accessible',
    });

    validateSnapshot.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DescribeSnapshots'],
      resources: ['*'],
    }));

    // Aggregate Results Lambda
    const aggregateResults = new lambdaNode.NodejsFunction(this, 'AggregateResultsFn', {
      ...commonProps,
      functionName: `${projectName}-${environment}-aggregate-results`,
      entry: require.resolve('@snapshot-sleuth/lambda-ts/src/handlers/aggregation'),
      description: 'Aggregates forensic tool results into case summary',
      timeout: cdk.Duration.minutes(10),
    });

    this.storage.evidenceBucket.grantReadWrite(aggregateResults);

    // Send Notification Lambda
    const sendNotification = new lambdaNode.NodejsFunction(this, 'SendNotificationFn', {
      ...commonProps,
      functionName: `${projectName}-${environment}-send-notification`,
      entry: require.resolve('@snapshot-sleuth/lambda-ts/src/handlers/send-notification'),
      description: 'Sends workflow completion notifications',
    });

    // Create Volume Lambda (creates EBS volume from snapshot)
    const createVolume = new lambda.Function(this, 'CreateVolumeFn', {
      ...commonProps,
      functionName: `${projectName}-${environment}-create-volume`,
      code: lambda.Code.fromInline(`
        const { EC2Client, CreateVolumeCommand, DescribeSnapshotsCommand } = require('@aws-sdk/client-ec2');
        const ec2 = new EC2Client({});

        exports.handler = async (event) => {
          const { snapshotId, availabilityZone } = event;

          // Get snapshot info
          const snapshot = await ec2.send(new DescribeSnapshotsCommand({
            SnapshotIds: [snapshotId]
          }));

          const volumeSize = snapshot.Snapshots[0].VolumeSize;

          // Create volume from snapshot
          const volume = await ec2.send(new CreateVolumeCommand({
            SnapshotId: snapshotId,
            AvailabilityZone: availabilityZone,
            VolumeType: 'gp3',
            Encrypted: true,
            TagSpecifications: [{
              ResourceType: 'volume',
              Tags: [
                { Key: 'Name', Value: \`forensics-\${event.caseId}\` },
                { Key: 'CaseId', Value: event.caseId },
                { Key: 'SnapshotId', Value: snapshotId },
                { Key: 'Purpose', Value: 'ForensicAnalysis' }
              ]
            }]
          }));

          return {
            volumeId: volume.VolumeId,
            volumeSize,
            snapshotId,
            caseId: event.caseId,
            availabilityZone
          };
        };
      `),
      handler: 'index.handler',
      description: 'Creates EBS volume from snapshot for forensic analysis',
    });

    createVolume.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'ec2:CreateVolume',
        'ec2:DescribeSnapshots',
        'ec2:CreateTags',
      ],
      resources: ['*'],
    }));

    kmsKey.grantEncryptDecrypt(createVolume);

    // Delete Volume Lambda (cleanup)
    const deleteVolume = new lambda.Function(this, 'DeleteVolumeFn', {
      ...commonProps,
      functionName: `${projectName}-${environment}-delete-volume`,
      code: lambda.Code.fromInline(`
        const { EC2Client, DeleteVolumeCommand } = require('@aws-sdk/client-ec2');
        const ec2 = new EC2Client({});

        exports.handler = async (event) => {
          const { volumeId } = event;

          await ec2.send(new DeleteVolumeCommand({
            VolumeId: volumeId
          }));

          return { volumeId, deleted: true };
        };
      `),
      handler: 'index.handler',
      description: 'Deletes EBS volume after forensic analysis',
    });

    deleteVolume.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DeleteVolume'],
      resources: ['*'],
    }));

    return {
      validateSnapshot,
      aggregateResults,
      sendNotification,
      createVolume,
      deleteVolume,
    };
  }

  /**
   * Create Step Functions workflow state machine
   */
  private createWorkflowStateMachine(
    projectName: string,
    environment: string,
    storage: StorageConstruct,
    monitoring: MonitoringConstruct,
    fargateStack: FargateForensicsStack,
    vpcStack: ForensicsVpcStack,
    lambdaFunctions: {
      validateSnapshot: lambda.Function;
      aggregateResults: lambda.Function;
      sendNotification: lambda.Function;
      createVolume: lambda.Function;
      deleteVolume: lambda.Function;
    }
  ): stepfunctions.StateMachine {
    // Step 1: Validate Snapshot
    const validateSnapshot = new tasks.LambdaInvoke(this, 'ValidateSnapshot', {
      lambdaFunction: lambdaFunctions.validateSnapshot,
      resultPath: '$.validation',
      retryOnServiceExceptions: true,
    });

    // Step 2: Generate Case ID
    const generateCaseId = new stepfunctions.Pass(this, 'GenerateCaseId', {
      parameters: {
        'caseId.$': "States.Format('case-{}', States.UUID())",
        'snapshotId.$': '$.snapshotId',
        'region.$': '$.region',
        'volumeSize.$': '$.validation.Payload.snapshot.volumeSize',
        'timestamp.$': '$$.State.EnteredTime',
      },
      resultPath: '$.case',
    });

    // Step 3: Create EBS Volume from Snapshot
    const createVolume = new tasks.LambdaInvoke(this, 'CreateEBSVolume', {
      lambdaFunction: lambdaFunctions.createVolume,
      payload: stepfunctions.TaskInput.fromObject({
        'snapshotId.$': '$.snapshotId',
        'caseId.$': '$.case.caseId',
        'availabilityZone.$': "States.Format('{}a', $.region)",
      }),
      resultPath: '$.volume',
      retryOnServiceExceptions: true,
    });

    // Step 4: Wait for Volume Available
    const waitForVolume = new stepfunctions.Wait(this, 'WaitForVolumeAvailable', {
      time: stepfunctions.WaitTime.duration(cdk.Duration.seconds(30)),
    });

    // Step 5: Run Forensic Tools in Parallel
    const runForensicTools = new stepfunctions.Parallel(this, 'RunForensicTools', {
      resultPath: '$.toolResults',
    });

    // Add each tool as a branch with error handling
    const tools = ['yara', 'clamav', 'evidence-miner', 'log2timeline'];
    for (const tool of tools) {
      const toolConfig = DEFAULT_TOOL_CONFIGS[tool];
      const isCritical = toolConfig.critical;

      // Create the Fargate task
      const runTask = new tasks.EcsRunTask(this, `Run${this.toPascalCase(tool)}`, {
        integrationPattern: stepfunctions.IntegrationPattern.RUN_JOB,
        cluster: fargateStack.cluster,
        taskDefinition: fargateStack.taskDefinitions[tool],
        launchTarget: new tasks.EcsFargateLaunchTarget({
          platformVersion: ecs.FargatePlatformVersion.LATEST,
        }),
        assignPublicIp: false,
        securityGroups: [vpcStack.forensicsSecurityGroup],
        subnets: { subnets: vpcStack.privateSubnets },
        containerOverrides: [{
          containerDefinition: fargateStack.taskDefinitions[tool].defaultContainer!,
          environment: [
            { name: 'CASE_ID', value: stepfunctions.JsonPath.stringAt('$.case.caseId') },
            { name: 'SNAPSHOT_ID', value: stepfunctions.JsonPath.stringAt('$.snapshotId') },
            { name: 'VOLUME_ID', value: stepfunctions.JsonPath.stringAt('$.volume.Payload.volumeId') },
          ],
        }],
        resultPath: '$.taskResult',
      });

      // Wrap in error handling
      const toolBranch = runTask.addCatch(
        new stepfunctions.Pass(this, `${this.toPascalCase(tool)}Failed`, {
          result: stepfunctions.Result.fromObject({
            toolName: tool,
            status: 'failed',
          }),
        }),
        {
          errors: ['States.ALL'],
          resultPath: '$.error',
        }
      );

      // Add retry for transient failures
      runTask.addRetry({
        errors: ['States.TaskFailed'],
        maxAttempts: isCritical ? 3 : 1,
        backoffRate: 2,
        interval: cdk.Duration.seconds(30),
      });

      runForensicTools.branch(toolBranch);
    }

    // Step 6: Aggregate Results
    const aggregateResults = new tasks.LambdaInvoke(this, 'AggregateResults', {
      lambdaFunction: lambdaFunctions.aggregateResults,
      payload: stepfunctions.TaskInput.fromObject({
        'caseId.$': '$.case.caseId',
        'snapshotId.$': '$.snapshotId',
        'evidenceBucket': storage.evidenceBucket.bucketName,
        'toolResults.$': '$.toolResults',
      }),
      resultPath: '$.aggregation',
    });

    // Step 7: Send Notification
    const sendNotification = new tasks.LambdaInvoke(this, 'SendNotification', {
      lambdaFunction: lambdaFunctions.sendNotification,
      payload: stepfunctions.TaskInput.fromObject({
        'caseId.$': '$.case.caseId',
        'snapshotId.$': '$.snapshotId',
        'status.$': '$.aggregation.Payload.status',
        'summaryUri.$': '$.aggregation.Payload.summaryUri',
        'totalFindings.$': '$.aggregation.Payload.totalFindings',
        'criticalFindings.$': '$.aggregation.Payload.criticalFindings',
      }),
      resultPath: '$.notification',
    });

    // Step 8: Cleanup (Delete EBS Volume)
    const cleanupVolume = new tasks.LambdaInvoke(this, 'CleanupVolume', {
      lambdaFunction: lambdaFunctions.deleteVolume,
      payload: stepfunctions.TaskInput.fromObject({
        'volumeId.$': '$.volume.Payload.volumeId',
      }),
      resultPath: '$.cleanup',
    });

    // Add catch for cleanup to ensure it runs even on failure
    cleanupVolume.addCatch(
      new stepfunctions.Pass(this, 'CleanupFailed', {
        result: stepfunctions.Result.fromObject({ cleanupFailed: true }),
      }),
      { errors: ['States.ALL'] }
    );

    // Success state
    const success = new stepfunctions.Succeed(this, 'WorkflowComplete', {
      comment: 'Forensic analysis completed successfully',
    });

    // Failure state
    const failure = new stepfunctions.Fail(this, 'WorkflowFailed', {
      cause: 'Forensic analysis failed',
      error: 'ForensicAnalysisFailed',
    });

    // Check aggregation status
    const checkStatus = new stepfunctions.Choice(this, 'CheckAnalysisStatus')
      .when(
        stepfunctions.Condition.stringEquals('$.aggregation.Payload.status', 'failed'),
        failure
      )
      .otherwise(success);

    // Define workflow
    const definition = validateSnapshot
      .next(generateCaseId)
      .next(createVolume)
      .next(waitForVolume)
      .next(runForensicTools)
      .next(aggregateResults)
      .next(sendNotification)
      .next(cleanupVolume)
      .next(checkStatus);

    // Create state machine
    const stateMachine = new stepfunctions.StateMachine(this, 'ForensicWorkflow', {
      stateMachineName: `${projectName}-${environment}-workflow`,
      definitionBody: stepfunctions.DefinitionBody.fromChainable(definition),
      logs: {
        destination: monitoring.logGroup,
        level: stepfunctions.LogLevel.ALL,
      },
      tracingEnabled: true,
      timeout: cdk.Duration.hours(6),
    });

    // Grant permissions
    fargateStack.cluster.grantTaskProtection(stateMachine);

    return stateMachine;
  }

  /**
   * Convert kebab-case to PascalCase
   */
  private toPascalCase(str: string): string {
    return str
      .split('-')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join('');
  }
}
