/**
 * Core types for the Snapshot Sleuth forensics system
 */

/**
 * Status of a forensic case
 */
export enum CaseStatus {
  CREATED = 'CREATED',
  IN_PROGRESS = 'IN_PROGRESS',
  ANALYSIS_COMPLETE = 'ANALYSIS_COMPLETE',
  REVIEW_REQUIRED = 'REVIEW_REQUIRED',
  CLOSED = 'CLOSED',
  FAILED = 'FAILED',
}

/**
 * Severity level for findings
 */
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

/**
 * Workflow execution status
 */
export enum WorkflowStatus {
  PENDING = 'PENDING',
  RUNNING = 'RUNNING',
  SUCCEEDED = 'SUCCEEDED',
  FAILED = 'FAILED',
  TIMEOUT = 'TIMEOUT',
  ABORTED = 'ABORTED',
}

/**
 * Forensic tool types
 */
export enum ForensicTool {
  YARA = 'YARA',
  CLAMAV = 'CLAMAV',
  WOLVERINE = 'WOLVERINE',
  LOG2TIMELINE = 'LOG2TIMELINE',
}

/**
 * Evidence metadata
 */
export interface Evidence {
  id: string;
  caseId: string;
  snapshotId: string;
  toolName: ForensicTool;
  artifactType: string;
  s3Bucket: string;
  s3Key: string;
  size: number;
  hash: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

/**
 * Tool execution result
 */
export interface ToolResult {
  toolName: ForensicTool;
  status: WorkflowStatus;
  executionArn?: string;
  startTime: string;
  endTime?: string;
  findings: Finding[];
  artifactUrls: string[];
  errorMessage?: string;
}

/**
 * Finding from forensic analysis
 */
export interface Finding {
  id: string;
  toolName: ForensicTool;
  severity: Severity;
  title: string;
  description: string;
  details: Record<string, unknown>;
  timestamp: string;
}

/**
 * Forensic case
 */
export interface Case {
  id: string;
  snapshotId: string;
  region: string;
  accountId: string;
  status: CaseStatus;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  priority: Severity;
  tags: Record<string, string>;
  metadata: Record<string, unknown>;
}

/**
 * Workflow execution details
 */
export interface WorkflowExecution {
  executionArn: string;
  caseId: string;
  status: WorkflowStatus;
  startTime: string;
  endTime?: string;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
}

/**
 * Snapshot details
 */
export interface Snapshot {
  snapshotId: string;
  volumeId: string;
  volumeSize: number;
  region: string;
  accountId: string;
  encrypted: boolean;
  kmsKeyId?: string;
  description?: string;
  tags: Record<string, string>;
  startTime: string;
}

/**
 * Case summary with aggregated results
 */
export interface CaseSummary extends Case {
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  toolResults: ToolResult[];
  workflowExecution?: WorkflowExecution;
}
