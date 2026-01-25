/**
 * Fargate forensic task types
 *
 * Types for the Fargate-based forensic analysis system.
 */

import { ForensicTool, Severity } from './case';

/**
 * Finding type categories
 */
export enum FindingType {
  MALWARE = 'malware',
  SUSPICIOUS_FILE = 'suspicious_file',
  CREDENTIAL = 'credential',
  PERSISTENCE = 'persistence',
  LATERAL_MOVEMENT = 'lateral_movement',
  DATA_EXFILTRATION = 'data_exfiltration',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  TIMELINE_ANOMALY = 'timeline_anomaly',
  CONFIGURATION_ISSUE = 'configuration_issue',
  OTHER = 'other',
}

/**
 * Tool execution status for Fargate tasks
 */
export type ToolExecutionStatus = 'success' | 'partial' | 'failed' | 'skipped';

/**
 * Normalized finding from forensic tools
 * Matches the Python Finding class structure
 */
export interface NormalizedFinding {
  /** Unique finding ID */
  id: string;
  /** Finding type category */
  type: FindingType;
  /** Severity level */
  severity: Severity;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  /** Path to affected file (if applicable) */
  filePath?: string;
  /** Line number in file (if applicable) */
  lineNumber?: number;
  /** Byte offset in file (if applicable) */
  offset?: number;
  /** Timestamp from artifact */
  timestamp?: string;
  /** When the finding was detected */
  detectedAt: string;
  /** Tool that produced this finding */
  toolName: string;
  /** Rule/signature name */
  ruleName?: string;
  /** Rule/signature ID */
  ruleId?: string;
  /** Confidence score (0-1) */
  confidence?: number;
  /** Indicators of compromise */
  indicators?: string[];
  /** Related file paths */
  relatedFiles?: string[];
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** MITRE ATT&CK tactic */
  mitreTactic?: string;
  /** MITRE ATT&CK technique */
  mitreTechnique?: string;
}

/**
 * Statistics from tool execution
 */
export interface ToolStatistics {
  /** Number of files scanned */
  filesScanned: number;
  /** Bytes processed */
  bytesScanned: number;
  /** Number of findings */
  findingsCount: number;
  /** Number of errors encountered */
  errorsCount: number;
  /** Number of warnings */
  warningsCount: number;
}

/**
 * Tool result from Fargate task
 * Matches the Python NormalizedResult structure
 */
export interface FargateToolResult {
  /** Tool name */
  toolName: string;
  /** Case ID */
  caseId: string;
  /** Snapshot ID analyzed */
  snapshotId: string;
  /** Execution status */
  status: ToolExecutionStatus;
  /** Start timestamp */
  startedAt: string;
  /** Completion timestamp */
  completedAt: string;
  /** Duration in seconds */
  durationSeconds: number;
  /** List of findings */
  findings: NormalizedFinding[];
  /** Execution statistics */
  statistics: ToolStatistics;
  /** Findings count by severity */
  severityCounts: Record<string, number>;
  /** Findings count by type */
  typeCounts: Record<string, number>;
  /** Tool version */
  toolVersion?: string;
  /** Signature/definition version */
  signatureVersion?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Tool execution result from Step Functions
 */
export interface ToolExecutionResult {
  /** Tool name */
  toolName: string;
  /** Execution status */
  status: ToolExecutionStatus;
  /** S3 URI of results.json */
  resultsUri?: string;
  /** Error message if failed */
  error?: string;
  /** Duration in seconds */
  durationSeconds?: number;
  /** ECS task ARN */
  taskArn?: string;
}

/**
 * Tool summary for case report
 */
export interface ToolSummary {
  /** Tool name */
  toolName: string;
  /** Execution status */
  status: string;
  /** Number of findings */
  findingsCount: number;
  /** Findings by severity */
  severityCounts: Record<string, number>;
  /** Duration in seconds */
  durationSeconds: number;
  /** Tool version used */
  toolVersion?: string;
}

/**
 * Aggregated case summary
 */
export interface AggregatedCaseSummary {
  /** Case ID */
  caseId: string;
  /** Snapshot ID analyzed */
  snapshotId: string;
  /** Generation timestamp */
  generatedAt: string;
  /** Overall status */
  status: 'completed' | 'partial' | 'failed';

  /** Total findings across all tools */
  totalFindings: number;
  /** Findings by severity */
  severityCounts: Record<string, number>;
  /** Findings by type */
  typeCounts: Record<string, number>;

  /** Number of tools executed */
  toolsExecuted: number;
  /** Number of tools succeeded */
  toolsSucceeded: number;
  /** Number of tools failed */
  toolsFailed: number;
  /** Total duration across all tools */
  totalDurationSeconds: number;

  /** Per-tool summaries */
  tools: ToolSummary[];

  /** Top findings (most severe) */
  topFindings: NormalizedFinding[];

  /** All findings grouped by severity */
  findings: {
    critical: NormalizedFinding[];
    high: NormalizedFinding[];
    medium: NormalizedFinding[];
    low: NormalizedFinding[];
    info: NormalizedFinding[];
  };
}

/**
 * Heartbeat event from Fargate task
 */
export interface ToolHeartbeat {
  /** Case ID */
  caseId: string;
  /** Tool name */
  tool: string;
  /** Snapshot ID */
  snapshotId: string;
  /** Heartbeat timestamp */
  timestamp: string;
  /** Heartbeat sequence number */
  heartbeatNumber: number;
  /** Elapsed seconds since start */
  elapsedSeconds: number;
  /** Progress information */
  progress: {
    percentComplete: number;
    currentPhase: string;
    itemsProcessed?: number;
    itemsTotal?: number;
    currentItem?: string;
    bytesProcessed?: number;
    bytesTotal?: number;
    findingsCount: number;
    errorsCount: number;
    warningsCount?: number;
  };
  /** Whether this is the final heartbeat */
  final?: boolean;
  /** Final status (only on final heartbeat) */
  status?: string;
  /** Summary data (only on final heartbeat) */
  summary?: Record<string, unknown>;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Resource allocation for a tool
 */
export interface ToolResourceAllocation {
  /** CPU units (1024 = 1 vCPU) */
  cpu: number;
  /** Memory in MB */
  memoryMb: number;
  /** Timeout in minutes */
  timeoutMinutes: number;
}

/**
 * Resource configuration for a forensic tool
 */
export interface ToolResourceConfig {
  /** Base CPU units */
  baseCpu: number;
  /** Base memory in MB */
  baseMemoryMb: number;
  /** Additional CPU per 100GB */
  cpuPer100Gb: number;
  /** Additional memory per 100GB */
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
  /** Whether tool failure aborts workflow */
  critical: boolean;
}

/**
 * Workflow input for forensic analysis
 */
export interface ForensicWorkflowInput {
  /** Snapshot ID to analyze */
  snapshotId: string;
  /** AWS region */
  region: string;
  /** Optional case ID (generated if not provided) */
  caseId?: string;
  /** Optional notification configuration */
  notification?: {
    email?: string;
    slack?: string;
    webhook?: string;
  };
  /** Optional tool overrides */
  toolOverrides?: {
    /** Tools to skip */
    skip?: string[];
    /** Custom resource allocations */
    resources?: Record<string, Partial<ToolResourceAllocation>>;
  };
}

/**
 * Workflow output from forensic analysis
 */
export interface ForensicWorkflowOutput {
  /** Case ID */
  caseId: string;
  /** Snapshot ID */
  snapshotId: string;
  /** Overall status */
  status: 'completed' | 'partial' | 'failed';
  /** S3 URI of case summary */
  summaryUri: string;
  /** Total findings */
  totalFindings: number;
  /** Critical findings count */
  criticalFindings: number;
  /** High findings count */
  highFindings: number;
  /** Tool execution results */
  toolResults: ToolExecutionResult[];
  /** Total duration in seconds */
  totalDurationSeconds: number;
}
