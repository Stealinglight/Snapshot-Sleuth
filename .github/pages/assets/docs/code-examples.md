---
layout: default
title: Code Examples
permalink: /code-examples/
description: Anonymized code examples demonstrating key patterns from the Snapshot-Sleuth implementation.
---

# Snapshot-Sleuth Code Examples

This document contains anonymized code examples demonstrating key patterns from the Snapshot-Sleuth implementation.

## Example 1: CDK Construct Pattern (TypeScript)

Reusable CDK construct for SQS queue with automatic dead-letter queue:

```typescript
import { Construct } from 'constructs';
import { Queue, QueueEncryption } from 'aws-cdk-lib/aws-sqs';

interface QueueProps {
  queueName: string;
  visibilityTimeout?: number;
  maxReceiveCount?: number;
}

export class ForensicQueue extends Construct {
  public readonly queue: Queue;
  public readonly dlq: Queue;

  constructor(scope: Construct, id: string, props: QueueProps) {
    super(scope, id);

    // Dead Letter Queue for failed messages
    this.dlq = new Queue(this, `${props.queueName}-DLQ`, {
      queueName: `${props.queueName}-DLQ`,
      encryption: QueueEncryption.KMS_MANAGED,
      retentionPeriod: Duration.days(14),
    });

    // Main queue with DLQ integration
    this.queue = new Queue(this, props.queueName, {
      queueName: props.queueName,
      encryption: QueueEncryption.KMS_MANAGED,
      visibilityTimeout: Duration.seconds(props.visibilityTimeout ?? 300),
      deadLetterQueue: {
        queue: this.dlq,
        maxReceiveCount: props.maxReceiveCount ?? 3,
      },
    });
  }
}
```

## Example 2: Step Functions State Machine with Task Token Callback (TypeScript)

Orchestrating EC2-based forensic analysis with callback pattern:

```typescript
import { Chain, StateMachine, TaskInput, JsonPath } from 'aws-cdk-lib/aws-stepfunctions';
import { LambdaInvoke, CallAwsService } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { IntegrationPattern } from 'aws-cdk-lib/aws-stepfunctions';

// Validation step
const validateSnapshot = new LambdaInvoke(this, 'ValidateSnapshot', {
  lambdaFunction: validationLambda,
  outputPath: '$.Payload',
});

// Copy snapshot (AWS API call)
const copySnapshot = new CallAwsService(this, 'CopySnapshot', {
  service: 'ec2',
  action: 'copySnapshot',
  parameters: {
    SourceSnapshotId: JsonPath.stringAt('$.snapshotId'),
    SourceRegion: JsonPath.stringAt('$.sourceRegion'),
    Encrypted: true,
  },
  iamResources: ['*'],
});

// Launch forensic EC2 with task token callback
const launchForensicInstance = new LambdaInvoke(this, 'LaunchForensicEC2', {
  lambdaFunction: instanceLauncher,
  integrationPattern: IntegrationPattern.WAIT_FOR_TASK_TOKEN,
  payload: TaskInput.fromObject({
    taskToken: JsonPath.taskToken,
    snapshotId: JsonPath.stringAt('$.copiedSnapshotId'),
    caseId: JsonPath.stringAt('$.caseId'),
  }),
  timeout: Duration.hours(8),
});

// Define workflow chain
const definition = validateSnapshot
  .next(new Parallel(this, 'ParallelOps')
    .branch(copySnapshot)
    .branch(launchForensicInstance))
  .next(notifyCompletion);

new StateMachine(this, 'SnapshotAnalysisMachine', {
  definition,
  tracingEnabled: true,
  logs: { destination: logGroup, level: LogLevel.ALL },
});
```

## Example 3: Lambda Handler with Powertools (TypeScript)

Lambda function with structured logging, metrics, and tracing:

```typescript
import { Logger } from '@aws-lambda-powertools/logger';
import { Metrics, MetricUnits } from '@aws-lambda-powertools/metrics';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';

const logger = new Logger({ serviceName: 'snapshot-sleuth-validator' });
const metrics = new Metrics({
  namespace: 'Sleuth/Workflow',
  serviceName: 'Validator'
});
const tracer = new Tracer({ serviceName: 'snapshot-sleuth-validator' });

const dynamodb = tracer.captureAWSv3Client(new DynamoDBClient({}));

interface SnapshotEvent {
  snapshotId: string;
  sourceAccount: string;
  sourceRegion: string;
  caseId: string;
}

export const handler = async (event: SnapshotEvent) => {
  logger.info('Processing snapshot', {
    snapshotId: event.snapshotId,
    caseId: event.caseId
  });

  const segment = tracer.getSegment();
  const subsegment = segment?.addNewSubsegment('ValidateSnapshot');

  try {
    // Validate snapshot exists and is shared
    const isValid = await validateSnapshotAccess(event.snapshotId);

    if (!isValid) {
      metrics.addMetric('ValidationFailed', MetricUnits.Count, 1);
      throw new Error(`Snapshot ${event.snapshotId} not accessible`);
    }

    // Record workflow start in DynamoDB
    await dynamodb.send(new PutItemCommand({
      TableName: process.env.TABLE_NAME,
      Item: {
        CaseID: { S: event.caseId },
        SnapshotID: { S: event.snapshotId },
        Status: { S: 'VALIDATING' },
        StartTime: { S: new Date().toISOString() },
      },
    }));

    metrics.addMetric('ValidationSucceeded', MetricUnits.Count, 1);
    subsegment?.addAnnotation('validated', true);

    return {
      ...event,
      validated: true,
      timestamp: Date.now(),
    };
  } catch (error) {
    subsegment?.addError(error as Error);
    logger.error('Validation failed', { error });
    throw error;
  } finally {
    subsegment?.close();
    metrics.publishStoredMetrics();
  }
};
```

## Example 4: Python Forensic Scanner with Timeout Protection

Scanner factory pattern with timeout protection for forensic tools:

```python
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional
from aws_lambda_powertools import Logger, Metrics
from aws_xray_sdk.core import xray_recorder

logger = Logger(service="snapshot-sleuth-scanner")
metrics = Metrics(namespace="Sleuth/Tools")


class TimeoutError(Exception):
    """Raised when scanner exceeds time limit."""
    pass


def timeout_handler(signum, frame):
    raise TimeoutError("Scanner execution timed out")


@dataclass
class ScanResult:
    tool_name: str
    success: bool
    detections: List[Dict]
    files_scanned: int
    execution_time_seconds: float
    error_message: Optional[str] = None


class ForensicScanner(ABC):
    """Abstract base class for forensic scanning tools."""

    def __init__(self, timeout_seconds: int = 3600):
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def scan(self, target_path: str) -> ScanResult:
        """Execute scan on target filesystem."""
        pass

    def execute_with_timeout(self, target_path: str) -> ScanResult:
        """Execute scan with timeout protection."""
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout_seconds)

        try:
            result = self.scan(target_path)
            return result
        except TimeoutError:
            logger.error(f"{self.__class__.__name__} timed out")
            return ScanResult(
                tool_name=self.__class__.__name__,
                success=False,
                detections=[],
                files_scanned=0,
                execution_time_seconds=self.timeout_seconds,
                error_message="Execution timed out"
            )
        finally:
            signal.alarm(0)


class YaraScanner(ForensicScanner):
    """YARA pattern matching scanner."""

    def __init__(self, rules_path: str, timeout_seconds: int = 3600):
        super().__init__(timeout_seconds)
        self.rules_path = rules_path

    @xray_recorder.capture("yara_scan")
    def scan(self, target_path: str) -> ScanResult:
        import yara
        import time
        import os

        start_time = time.time()
        detections = []
        files_scanned = 0

        # Compile YARA rules
        rules = yara.compile(filepath=self.rules_path)

        # Scan filesystem
        for root, dirs, files in os.walk(target_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    matches = rules.match(filepath, timeout=60)
                    files_scanned += 1

                    if matches:
                        detections.append({
                            "file": filepath,
                            "rules": [m.rule for m in matches],
                            "tags": [tag for m in matches for tag in m.tags]
                        })
                except Exception as e:
                    logger.warning(f"Error scanning {filepath}: {e}")

        execution_time = time.time() - start_time

        # Emit metrics
        metrics.add_metric(
            name="ToolExecutionTime",
            unit="Seconds",
            value=execution_time
        )
        metrics.add_metric(
            name="DetectionCount",
            unit="Count",
            value=len(detections)
        )

        return ScanResult(
            tool_name="YARA",
            success=True,
            detections=detections,
            files_scanned=files_scanned,
            execution_time_seconds=execution_time
        )


class ScannerFactory:
    """Factory for creating forensic scanners."""

    _scanners = {
        "yara": YaraScanner,
        "clamav": lambda: ClamAVScanner(),
        "artifacts": lambda: ArtifactCollector(),
        "timeline": lambda: TimelineGenerator(),
    }

    @classmethod
    def create(cls, scanner_type: str, **kwargs) -> ForensicScanner:
        if scanner_type not in cls._scanners:
            raise ValueError(f"Unknown scanner type: {scanner_type}")
        return cls._scanners[scanner_type](**kwargs)
```

## Example 5: EventBridge Metrics Processor (Python)

Processing Step Functions state changes for CloudWatch metrics:

```python
import json
import boto3
from datetime import datetime
from aws_lambda_powertools import Logger, Metrics
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger(service="snapshot-sleuth-metrics")
metrics = Metrics(namespace="Sleuth/Workflow")

sfn_client = boto3.client("stepfunctions")


def handler(event: dict, context: LambdaContext) -> dict:
    """Process Step Functions EventBridge events and emit CloudWatch metrics."""

    detail = event.get("detail", {})
    status = detail.get("status")
    execution_arn = detail.get("executionArn")
    state_machine_arn = detail.get("stateMachineArn")

    logger.info("Processing execution event", extra={
        "status": status,
        "execution_arn": execution_arn
    })

    # Extract state machine name for dimensions
    sm_name = state_machine_arn.split(":")[-1] if state_machine_arn else "unknown"

    # Add common dimensions
    metrics.add_dimension(name="StateMachine", value=sm_name)
    metrics.add_dimension(name="Region", value=context.invoked_function_arn.split(":")[3])

    if status == "RUNNING":
        metrics.add_metric(name="ExecutionStarted", unit="Count", value=1)

    elif status == "SUCCEEDED":
        metrics.add_metric(name="ExecutionSucceeded", unit="Count", value=1)

        # Calculate and emit duration
        if execution_arn:
            duration = calculate_execution_duration(execution_arn)
            metrics.add_metric(
                name="ExecutionDuration",
                unit="Milliseconds",
                value=duration
            )

    elif status == "FAILED":
        metrics.add_metric(name="ExecutionFailed", unit="Count", value=1)

        # Log failure details
        if execution_arn:
            error_info = get_execution_error(execution_arn)
            logger.error("Execution failed", extra=error_info)

    elif status == "TIMED_OUT":
        metrics.add_metric(name="ExecutionTimedOut", unit="Count", value=1)

    metrics.flush_metrics()

    return {"processed": True, "status": status}


def calculate_execution_duration(execution_arn: str) -> float:
    """Get execution duration in milliseconds."""
    response = sfn_client.describe_execution(executionArn=execution_arn)

    start_time = response["startDate"]
    stop_time = response.get("stopDate", datetime.now(start_time.tzinfo))

    duration = (stop_time - start_time).total_seconds() * 1000
    return duration


def get_execution_error(execution_arn: str) -> dict:
    """Extract error details from failed execution."""
    response = sfn_client.describe_execution(executionArn=execution_arn)

    return {
        "error": response.get("error", "Unknown"),
        "cause": response.get("cause", "No cause provided"),
        "execution_arn": execution_arn
    }
```

## Example 6: React Query Hook for Dashboard (TypeScript/React)

Data fetching pattern with React Query for real-time dashboard updates:

```typescript
import { useQuery, useMutation, useQueryClient } from 'react-query';

interface Engagement {
  caseId: string;
  snapshotId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  startTime: string;
  completionTime?: string;
  evidenceLocation?: string;
}

interface EngagementFilters {
  status?: string;
  dateRange?: { start: string; end: string };
}

// Fetch engagements with automatic refresh
export const useEngagements = (filters?: EngagementFilters) => {
  return useQuery<Engagement[]>(
    ['engagements', filters],
    async () => {
      const params = new URLSearchParams();
      if (filters?.status) params.append('status', filters.status);
      if (filters?.dateRange) {
        params.append('startDate', filters.dateRange.start);
        params.append('endDate', filters.dateRange.end);
      }

      const response = await fetch(`/api/engagements?${params}`, {
        credentials: 'include', // SSO authentication
      });

      if (!response.ok) {
        throw new Error('Failed to fetch engagements');
      }

      return response.json();
    },
    {
      refetchInterval: 30000, // Refresh every 30 seconds
      staleTime: 10000,       // Consider data stale after 10 seconds
      retry: 3,
    }
  );
};

// Fetch single engagement details
export const useEngagementDetails = (caseId: string) => {
  return useQuery<Engagement>(
    ['engagement', caseId],
    async () => {
      const response = await fetch(`/api/engagements/${caseId}`, {
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch engagement details');
      }

      return response.json();
    },
    {
      enabled: !!caseId, // Only fetch when caseId is provided
      refetchInterval: 5000, // More frequent refresh for detail view
    }
  );
};

// Submit new snapshot for analysis
export const useSubmitSnapshot = () => {
  const queryClient = useQueryClient();

  return useMutation(
    async (data: { snapshotId: string; caseId: string; sourceRegion: string }) => {
      const response = await fetch('/api/engagements', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error('Failed to submit snapshot');
      }

      return response.json();
    },
    {
      onSuccess: () => {
        // Invalidate and refetch engagements list
        queryClient.invalidateQueries('engagements');
      },
    }
  );
};
```

## Example 7: X-Ray Tracing Decorator (Python)

Decorator pattern for automatic X-Ray tracing with graceful degradation:

```python
from functools import wraps
from typing import Callable, Optional
import os

# Check if X-Ray is available
XRAY_ENABLED = os.environ.get("AWS_XRAY_DAEMON_ADDRESS") is not None

if XRAY_ENABLED:
    from aws_xray_sdk.core import xray_recorder
    from aws_xray_sdk.core import patch_all
    patch_all()


def trace(
    name: Optional[str] = None,
    namespace: str = "Sleuth",
    capture_response: bool = False
) -> Callable:
    """
    Decorator for X-Ray tracing with graceful degradation.

    Args:
        name: Segment name (defaults to function name)
        namespace: X-Ray namespace for grouping
        capture_response: Whether to capture return value in metadata

    Usage:
        @trace(name="scan_filesystem", namespace="Sleuth/Tools")
        def perform_scan(path: str) -> dict:
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not XRAY_ENABLED:
                # X-Ray not available, execute without tracing
                return func(*args, **kwargs)

            segment_name = name or func.__name__

            # Create subsegment within current context
            with xray_recorder.in_subsegment(segment_name) as subsegment:
                subsegment.put_annotation("namespace", namespace)
                subsegment.put_annotation("function", func.__name__)

                try:
                    result = func(*args, **kwargs)

                    if capture_response and result is not None:
                        # Safely capture response metadata
                        try:
                            subsegment.put_metadata("response", result)
                        except Exception:
                            pass  # Don't fail if response can't be serialized

                    return result

                except Exception as e:
                    subsegment.add_exception(e, stack=True)
                    raise

        return wrapper
    return decorator


# Usage examples
@trace(name="mount_filesystem", namespace="Sleuth/Storage")
def mount_image(image_path: str, mount_point: str) -> bool:
    """Mount forensic image at specified location."""
    import subprocess

    result = subprocess.run(
        ["mount", "-o", "ro,loop", image_path, mount_point],
        capture_output=True
    )
    return result.returncode == 0


@trace(name="collect_artifacts", namespace="Sleuth/Forensics", capture_response=True)
def collect_system_artifacts(mount_point: str) -> dict:
    """Collect forensic artifacts from mounted filesystem."""
    artifacts = {
        "user_files": [],
        "browser_history": [],
        "registry_keys": [],
        "event_logs": [],
    }

    # Collection logic here...

    return artifacts
```

## Example 8: Dashboard Widget Configuration (TypeScript CDK)

Modular dashboard construct for CloudWatch monitoring:

```typescript
import { Construct } from 'constructs';
import {
  Dashboard,
  GraphWidget,
  SingleValueWidget,
  TextWidget,
  Metric,
  Row
} from 'aws-cdk-lib/aws-cloudwatch';

interface DashboardProps {
  stageName: string;
  region: string;
  stateMachineArn: string;
}

export class ForensicsWorkflowDashboard extends Construct {
  public readonly dashboard: Dashboard;

  constructor(scope: Construct, id: string, props: DashboardProps) {
    super(scope, id);

    const dashboardName = `Sleuth-${props.stageName}-${props.region}-Workflow`;

    this.dashboard = new Dashboard(this, 'Dashboard', {
      dashboardName,
      defaultInterval: Duration.hours(3),
    });

    // Header row
    this.dashboard.addWidgets(
      new TextWidget({
        markdown: `# Forensic Workflow Dashboard\n**Stage:** ${props.stageName} | **Region:** ${props.region}`,
        width: 24,
        height: 1,
      })
    );

    // Key metrics row
    this.dashboard.addWidgets(
      this.createExecutionCountWidget(),
      this.createSuccessRateWidget(),
      this.createAverageDurationWidget(),
      this.createActiveExecutionsWidget(),
    );

    // Execution timeline
    this.dashboard.addWidgets(
      this.createExecutionTimelineWidget(props.stateMachineArn),
    );

    // Duration breakdown
    this.dashboard.addWidgets(
      this.createDurationBreakdownWidget(),
      this.createToolPerformanceWidget(),
    );
  }

  private createExecutionCountWidget(): SingleValueWidget {
    return new SingleValueWidget({
      title: 'Executions Today',
      metrics: [
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionStarted',
          statistic: 'Sum',
          period: Duration.days(1),
        }),
      ],
      width: 6,
      height: 4,
    });
  }

  private createSuccessRateWidget(): SingleValueWidget {
    return new SingleValueWidget({
      title: 'Success Rate',
      metrics: [
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionSucceeded',
          statistic: 'Average',
          period: Duration.hours(24),
        }),
      ],
      width: 6,
      height: 4,
    });
  }

  private createAverageDurationWidget(): SingleValueWidget {
    return new SingleValueWidget({
      title: 'Avg Duration (min)',
      metrics: [
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionDuration',
          statistic: 'Average',
          period: Duration.hours(24),
        }),
      ],
      width: 6,
      height: 4,
    });
  }

  private createActiveExecutionsWidget(): SingleValueWidget {
    return new SingleValueWidget({
      title: 'Active Executions',
      metrics: [
        new Metric({
          namespace: 'AWS/States',
          metricName: 'ExecutionsRunning',
          statistic: 'Maximum',
          period: Duration.minutes(5),
        }),
      ],
      width: 6,
      height: 4,
    });
  }

  private createExecutionTimelineWidget(stateMachineArn: string): GraphWidget {
    return new GraphWidget({
      title: 'Execution Timeline',
      left: [
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionStarted',
          statistic: 'Sum',
          period: Duration.hours(1),
          color: '#2196f3',
        }),
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionSucceeded',
          statistic: 'Sum',
          period: Duration.hours(1),
          color: '#4caf50',
        }),
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionFailed',
          statistic: 'Sum',
          period: Duration.hours(1),
          color: '#f44336',
        }),
      ],
      width: 24,
      height: 6,
    });
  }

  private createDurationBreakdownWidget(): GraphWidget {
    return new GraphWidget({
      title: 'Execution Duration Distribution',
      left: [
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionDuration',
          statistic: 'p50',
          period: Duration.hours(1),
          label: 'p50',
        }),
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionDuration',
          statistic: 'p90',
          period: Duration.hours(1),
          label: 'p90',
        }),
        new Metric({
          namespace: 'Sleuth/Workflow',
          metricName: 'ExecutionDuration',
          statistic: 'p99',
          period: Duration.hours(1),
          label: 'p99',
        }),
      ],
      width: 12,
      height: 6,
    });
  }

  private createToolPerformanceWidget(): GraphWidget {
    return new GraphWidget({
      title: 'Tool Execution Time',
      left: [
        new Metric({
          namespace: 'Sleuth/Tools',
          metricName: 'ToolExecutionTime',
          dimensionsMap: { Tool: 'YARA' },
          statistic: 'Average',
          period: Duration.hours(1),
          label: 'YARA',
        }),
        new Metric({
          namespace: 'Sleuth/Tools',
          metricName: 'ToolExecutionTime',
          dimensionsMap: { Tool: 'ClamAV' },
          statistic: 'Average',
          period: Duration.hours(1),
          label: 'ClamAV',
        }),
        new Metric({
          namespace: 'Sleuth/Tools',
          metricName: 'ToolExecutionTime',
          dimensionsMap: { Tool: 'Artifacts' },
          statistic: 'Average',
          period: Duration.hours(1),
          label: 'Artifacts',
        }),
      ],
      width: 12,
      height: 6,
    });
  }
}
```

---

## Code Example Summary

| Example | Language | Pattern | Key Concept |
|---------|----------|---------|-------------|
| 1 | TypeScript CDK | Construct | Reusable infrastructure component |
| 2 | TypeScript CDK | Step Functions | Task token callback pattern |
| 3 | TypeScript | Lambda Powertools | Observability integration |
| 4 | Python | Factory + Timeout | Scanner abstraction with protection |
| 5 | Python | EventBridge Processor | Metrics emission pattern |
| 6 | TypeScript/React | React Query | Data fetching with auto-refresh |
| 7 | Python | Decorator | X-Ray tracing with graceful degradation |
| 8 | TypeScript CDK | Dashboard | CloudWatch widget configuration |
