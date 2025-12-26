/**
 * Shared utility functions
 */
import { randomBytes, createHash } from 'crypto';

/**
 * Generate a unique case ID
 */
export function generateCaseId(prefix = 'CASE'): string {
  const timestamp = Date.now();
  const random = randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}-${timestamp}-${random}`;
}

/**
 * Generate a unique finding ID
 */
export function generateFindingId(toolName: string): string {
  const timestamp = Date.now();
  const random = randomBytes(2).toString('hex').toUpperCase();
  return `${toolName.toUpperCase()}-${timestamp}-${random}`;
}

/**
 * Calculate SHA-256 hash of a string
 */
export function calculateHash(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Format timestamp to ISO string
 */
export function formatTimestamp(date: Date = new Date()): string {
  return date.toISOString();
}

/**
 * Parse ISO timestamp
 */
export function parseTimestamp(timestamp: string): Date {
  return new Date(timestamp);
}

/**
 * Calculate duration between two timestamps in milliseconds
 */
export function calculateDuration(startTime: string, endTime: string): number {
  return parseTimestamp(endTime).getTime() - parseTimestamp(startTime).getTime();
}

/**
 * Format duration to human-readable string
 */
export function formatDuration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
}

/**
 * Sanitize string for use in S3 keys
 */
export function sanitizeS3Key(key: string): string {
  return key.replace(/[^a-zA-Z0-9-_./]/g, '_');
}

/**
 * Build S3 URI
 */
export function buildS3Uri(bucket: string, key: string): string {
  return `s3://${bucket}/${key}`;
}

/**
 * Parse S3 URI
 */
export function parseS3Uri(uri: string): { bucket: string; key: string } | null {
  const match = uri.match(/^s3:\/\/([^/]+)\/(.+)$/);
  if (!match) {
    return null;
  }
  return {
    bucket: match[1],
    key: match[2],
  };
}

/**
 * Check if value is defined (not null or undefined)
 */
export function isDefined<T>(value: T | null | undefined): value is T {
  return value !== null && value !== undefined;
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retry function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    maxAttempts?: number;
    initialDelay?: number;
    maxDelay?: number;
    backoffMultiplier?: number;
  } = {}
): Promise<T> {
  const {
    maxAttempts = 3,
    initialDelay = 1000,
    maxDelay = 30000,
    backoffMultiplier = 2,
  } = options;

  let lastError: Error | undefined;
  let delay = initialDelay;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts) {
        await sleep(Math.min(delay, maxDelay));
        delay *= backoffMultiplier;
      }
    }
  }

  throw lastError;
}
