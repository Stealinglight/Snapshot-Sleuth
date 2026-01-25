/**
 * Result Aggregation Handler
 *
 * Aggregates forensic tool results from S3 into a unified case summary.
 * Called by Step Functions after all forensic tools complete.
 */
import { Handler } from 'aws-lambda';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { createLogger } from '@snapshot-sleuth/shared';

const logger = createLogger();
const s3 = new S3Client({});

/**
 * Input event from Step Functions
 */
export interface AggregationEvent {
  caseId: string;
  snapshotId: string;
  evidenceBucket: string;
  toolResults: ToolExecutionResult[];
}

/**
 * Result from individual tool execution
 */
export interface ToolExecutionResult {
  toolName: string;
  status: 'success' | 'partial' | 'failed' | 'skipped';
  resultsUri?: string;
  error?: string;
  durationSeconds?: number;
}

/**
 * Normalized finding from forensic tools
 */
export interface Finding {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  filePath?: string;
  timestamp?: string;
  detectedAt: string;
  toolName: string;
  ruleName?: string;
  confidence?: number;
  indicators?: string[];
  mitreTactic?: string;
  mitreTechnique?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Tool result structure from S3
 */
export interface ToolResult {
  toolName: string;
  caseId: string;
  snapshotId: string;
  status: string;
  startedAt: string;
  completedAt: string;
  durationSeconds: number;
  findings: Finding[];
  statistics: {
    filesScanned: number;
    bytesScanned: number;
    findingsCount: number;
    errorsCount: number;
    warningsCount: number;
  };
  severityCounts: Record<string, number>;
  typeCounts: Record<string, number>;
  toolVersion?: string;
  signatureVersion?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Aggregated case summary
 */
export interface CaseSummary {
  caseId: string;
  snapshotId: string;
  generatedAt: string;
  status: 'completed' | 'partial' | 'failed';

  // Aggregated statistics
  totalFindings: number;
  severityCounts: Record<string, number>;
  typeCounts: Record<string, number>;

  // Tool execution summary
  toolsExecuted: number;
  toolsSucceeded: number;
  toolsFailed: number;
  totalDurationSeconds: number;

  // Per-tool summaries
  tools: ToolSummary[];

  // Top findings (most severe)
  topFindings: Finding[];

  // All findings by severity
  findings: {
    critical: Finding[];
    high: Finding[];
    medium: Finding[];
    low: Finding[];
    info: Finding[];
  };
}

/**
 * Summary for a single tool
 */
export interface ToolSummary {
  toolName: string;
  status: string;
  findingsCount: number;
  severityCounts: Record<string, number>;
  durationSeconds: number;
  toolVersion?: string;
}

/**
 * Output returned to Step Functions
 */
export interface AggregationResult {
  caseId: string;
  snapshotId: string;
  summaryUri: string;
  status: 'completed' | 'partial' | 'failed';
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
}

export const handler: Handler<AggregationEvent, AggregationResult> = async (event) => {
  logger.info('Starting result aggregation', {
    caseId: event.caseId,
    toolCount: event.toolResults.length,
  });

  const toolResults: ToolResult[] = [];
  const allFindings: Finding[] = [];

  // Fetch results from each tool
  for (const toolExec of event.toolResults) {
    if (toolExec.status === 'skipped') {
      logger.info('Skipping tool with no results', { tool: toolExec.toolName });
      continue;
    }

    try {
      const result = await fetchToolResult(
        event.evidenceBucket,
        event.caseId,
        toolExec.toolName
      );

      if (result) {
        toolResults.push(result);
        allFindings.push(...result.findings);
        logger.info('Fetched tool results', {
          tool: toolExec.toolName,
          findings: result.findings.length,
        });
      }
    } catch (error) {
      logger.warn('Failed to fetch tool results', {
        tool: toolExec.toolName,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Generate case summary
  const summary = generateCaseSummary(
    event.caseId,
    event.snapshotId,
    event.toolResults,
    toolResults,
    allFindings
  );

  // Upload summary to S3
  const summaryKey = `cases/${event.caseId}/summary.json`;
  await s3.send(new PutObjectCommand({
    Bucket: event.evidenceBucket,
    Key: summaryKey,
    Body: JSON.stringify(summary, null, 2),
    ContentType: 'application/json',
    ServerSideEncryption: 'aws:kms',
  }));

  logger.info('Aggregation complete', {
    caseId: event.caseId,
    totalFindings: summary.totalFindings,
    status: summary.status,
  });

  return {
    caseId: event.caseId,
    snapshotId: event.snapshotId,
    summaryUri: `s3://${event.evidenceBucket}/${summaryKey}`,
    status: summary.status,
    totalFindings: summary.totalFindings,
    criticalFindings: summary.severityCounts.critical || 0,
    highFindings: summary.severityCounts.high || 0,
  };
};

/**
 * Fetch tool result JSON from S3
 */
async function fetchToolResult(
  bucket: string,
  caseId: string,
  toolName: string
): Promise<ToolResult | null> {
  const key = `cases/${caseId}/${toolName}/results.json`;

  try {
    const response = await s3.send(new GetObjectCommand({
      Bucket: bucket,
      Key: key,
    }));

    const body = await response.Body?.transformToString();
    if (!body) {
      return null;
    }

    return JSON.parse(body) as ToolResult;
  } catch (error) {
    // File might not exist if tool failed
    return null;
  }
}

/**
 * Generate aggregated case summary
 */
function generateCaseSummary(
  caseId: string,
  snapshotId: string,
  toolExecutions: ToolExecutionResult[],
  toolResults: ToolResult[],
  allFindings: Finding[]
): CaseSummary {
  // Calculate overall status
  const criticalTools = toolExecutions.filter(t =>
    ['yara', 'evidence-miner', 'log2timeline'].includes(t.toolName)
  );
  const criticalFailures = criticalTools.filter(t => t.status === 'failed').length;

  let status: 'completed' | 'partial' | 'failed';
  if (criticalFailures > 0) {
    status = 'failed';
  } else if (toolExecutions.some(t => t.status === 'failed' || t.status === 'partial')) {
    status = 'partial';
  } else {
    status = 'completed';
  }

  // Aggregate severity counts
  const severityCounts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const typeCounts: Record<string, number> = {};

  for (const finding of allFindings) {
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
    typeCounts[finding.type] = (typeCounts[finding.type] || 0) + 1;
  }

  // Sort findings by severity
  const findingsBySeverity = {
    critical: allFindings.filter(f => f.severity === 'critical'),
    high: allFindings.filter(f => f.severity === 'high'),
    medium: allFindings.filter(f => f.severity === 'medium'),
    low: allFindings.filter(f => f.severity === 'low'),
    info: allFindings.filter(f => f.severity === 'info'),
  };

  // Get top findings (critical + high, limited)
  const topFindings = [
    ...findingsBySeverity.critical.slice(0, 10),
    ...findingsBySeverity.high.slice(0, 10),
  ].slice(0, 15);

  // Build tool summaries
  const toolSummaries: ToolSummary[] = toolResults.map(result => ({
    toolName: result.toolName,
    status: result.status,
    findingsCount: result.findings.length,
    severityCounts: result.severityCounts,
    durationSeconds: result.durationSeconds,
    toolVersion: result.toolVersion,
  }));

  // Add failed tools that didn't produce results
  for (const exec of toolExecutions) {
    if (!toolResults.find(r => r.toolName === exec.toolName)) {
      toolSummaries.push({
        toolName: exec.toolName,
        status: exec.status,
        findingsCount: 0,
        severityCounts: {},
        durationSeconds: exec.durationSeconds || 0,
      });
    }
  }

  // Calculate total duration
  const totalDuration = toolResults.reduce((sum, r) => sum + r.durationSeconds, 0);

  return {
    caseId,
    snapshotId,
    generatedAt: new Date().toISOString(),
    status,
    totalFindings: allFindings.length,
    severityCounts,
    typeCounts,
    toolsExecuted: toolExecutions.length,
    toolsSucceeded: toolExecutions.filter(t => t.status === 'success').length,
    toolsFailed: toolExecutions.filter(t => t.status === 'failed').length,
    totalDurationSeconds: totalDuration,
    tools: toolSummaries,
    topFindings,
    findings: findingsBySeverity,
  };
}
