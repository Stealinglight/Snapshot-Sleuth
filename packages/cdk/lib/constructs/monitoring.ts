/**
 * Monitoring construct for CloudWatch dashboards and alarms
 */
import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface MonitoringConstructProps {
  projectName: string;
  environment: string;
  alarmEmail?: string;
}

export class MonitoringConstruct extends Construct {
  public readonly dashboard: cloudwatch.Dashboard;
  public readonly alarmTopic: sns.Topic;
  public readonly logGroup: logs.LogGroup;

  constructor(scope: Construct, id: string, props: MonitoringConstructProps) {
    super(scope, id);

    // Create SNS topic for alarms
    this.alarmTopic = new sns.Topic(this, 'AlarmTopic', {
      displayName: `${props.projectName}-${props.environment}-alarms`,
      topicName: `${props.projectName}-${props.environment}-alarms`,
    });

    if (props.alarmEmail) {
      this.alarmTopic.addSubscription(
        new subscriptions.EmailSubscription(props.alarmEmail)
      );
    }

    // Create CloudWatch dashboard
    this.dashboard = new cloudwatch.Dashboard(this, 'Dashboard', {
      dashboardName: `${props.projectName}-${props.environment}`,
    });

    // Create log group for application logs
    this.logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `/aws/${props.projectName}/${props.environment}`,
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add basic widgets
    this.dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: `# ${props.projectName} - ${props.environment}
        
Automated Cloud Forensics and Incident Response Dashboard`,
        width: 24,
        height: 2,
      })
    );
  }

  /**
   * Add workflow metrics to dashboard
   */
  addWorkflowMetrics(_stateMachineArn: string): void {
    const namespace = 'AWS/States';

    this.dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: 'Workflow Executions',
        width: 12,
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'ExecutionsStarted',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
          new cloudwatch.Metric({
            namespace,
            metricName: 'ExecutionsSucceeded',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
          new cloudwatch.Metric({
            namespace,
            metricName: 'ExecutionsFailed',
            statistic: 'Sum',
            period: cdk.Duration.minutes(5),
          }),
        ],
      }),
      new cloudwatch.GraphWidget({
        title: 'Execution Duration',
        width: 12,
        left: [
          new cloudwatch.Metric({
            namespace,
            metricName: 'ExecutionTime',
            statistic: 'Average',
            period: cdk.Duration.minutes(5),
          }),
        ],
      })
    );

    // Create alarm for failed executions
    const failedExecutionsAlarm = new cloudwatch.Alarm(this, 'FailedExecutionsAlarm', {
      metric: new cloudwatch.Metric({
        namespace,
        metricName: 'ExecutionsFailed',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 1,
      evaluationPeriods: 1,
      alarmDescription: 'Alert when workflow executions fail',
    });

    failedExecutionsAlarm.addAlarmAction({
      bind: () => ({ alarmActionArn: this.alarmTopic.topicArn }),
    });
  }
}
