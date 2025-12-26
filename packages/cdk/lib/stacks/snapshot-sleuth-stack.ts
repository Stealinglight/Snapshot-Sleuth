/**
 * Main Snapshot Sleuth stack
 */
import * as cdk from 'aws-cdk-lib';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import { Construct } from 'constructs';
import { StorageConstruct, MonitoringConstruct } from '../constructs';

export class SnapshotSleuthStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
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
    const storage = new StorageConstruct(this, 'Storage', {
      bucketPrefix: projectName,
      environment,
      kmsKey: encryptionKey,
    });

    // Create monitoring resources
    const monitoring = new MonitoringConstruct(this, 'Monitoring', {
      projectName,
      environment,
      alarmEmail: this.node.tryGetContext('alarmEmail'),
    });

    // Enable CloudTrail
    new cloudtrail.Trail(this, 'AuditTrail', {
      trailName: `${projectName}-${environment}`,
      bucket: storage.logsBucket,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      managementEvents: cloudtrail.ReadWriteType.ALL,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: monitoring.logGroup,
    });

    // Create Step Functions state machine
    const stateMachine = this.createWorkflowStateMachine(
      projectName,
      environment,
      storage,
      monitoring
    );

    // Add workflow metrics to dashboard
    monitoring.addWorkflowMetrics(stateMachine.stateMachineArn);

    // Outputs
    new cdk.CfnOutput(this, 'StateMachineArn', {
      value: stateMachine.stateMachineArn,
      description: 'Forensic workflow state machine ARN',
    });

    new cdk.CfnOutput(this, 'EvidenceBucketName', {
      value: storage.evidenceBucket.bucketName,
      description: 'Evidence storage bucket name',
    });

    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${monitoring.dashboard.dashboardName}`,
      description: 'CloudWatch dashboard URL',
    });
  }

  private createWorkflowStateMachine(
    projectName: string,
    environment: string,
    storage: StorageConstruct,
    monitoring: MonitoringConstruct
  ): stepfunctions.StateMachine {
    // Define workflow steps
    const validateSnapshot = new stepfunctions.Pass(this, 'ValidateSnapshot', {
      comment: 'Validate snapshot exists and is accessible',
      parameters: {
        'snapshotId.$': '$.snapshotId',
        'region.$': '$.region',
        'validated': true,
      },
    });

    const copySnapshot = new stepfunctions.Pass(this, 'CopySnapshot', {
      comment: 'Copy snapshot to analysis region if needed',
    });

    const provisionEnvironment = new stepfunctions.Pass(this, 'ProvisionEnvironment', {
      comment: 'Provision isolated analysis environment',
    });

    const runForensicTools = new stepfunctions.Parallel(this, 'RunForensicTools', {
      comment: 'Execute forensic tool pipeline',
    });

    // Add forensic tool branches
    runForensicTools.branch(
      new stepfunctions.Pass(this, 'RunYARA', {
        comment: 'Run YARA rule-based detection',
      })
    );

    runForensicTools.branch(
      new stepfunctions.Pass(this, 'RunClamAV', {
        comment: 'Run ClamAV malware scanning',
      })
    );

    runForensicTools.branch(
      new stepfunctions.Pass(this, 'RunWolverine', {
        comment: 'Run Wolverine artifact extraction',
      })
    );

    runForensicTools.branch(
      new stepfunctions.Pass(this, 'RunLog2Timeline', {
        comment: 'Run Log2Timeline timeline generation',
      })
    );

    const uploadEvidence = new stepfunctions.Pass(this, 'UploadEvidence', {
      comment: 'Upload evidence and artifacts to S3',
      parameters: {
        'evidenceBucket': storage.evidenceBucket.bucketName,
        'artifactsBucket': storage.artifactsBucket.bucketName,
      },
    });

    const sendNotification = new stepfunctions.Pass(this, 'SendNotification', {
      comment: 'Send completion notification',
    });

    const cleanupEnvironment = new stepfunctions.Pass(this, 'CleanupEnvironment', {
      comment: 'Cleanup analysis environment',
    });

    // Define workflow
    const definition = validateSnapshot
      .next(copySnapshot)
      .next(provisionEnvironment)
      .next(runForensicTools)
      .next(uploadEvidence)
      .next(sendNotification)
      .next(cleanupEnvironment);

    // Create state machine
    const stateMachine = new stepfunctions.StateMachine(this, 'ForensicWorkflow', {
      stateMachineName: `${projectName}-${environment}-workflow`,
      definition,
      logs: {
        destination: monitoring.logGroup,
        level: stepfunctions.LogLevel.ALL,
      },
      tracingEnabled: true,
    });

    return stateMachine;
  }
}
