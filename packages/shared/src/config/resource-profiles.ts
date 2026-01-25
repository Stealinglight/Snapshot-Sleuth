/**
 * Resource profiles for Fargate forensic tools
 *
 * Based on the design document's resource allocation matrix.
 * Resources scale with snapshot size for optimal performance.
 */
import { z } from 'zod';
import { ToolResourceConfig } from '../types/fargate';

/**
 * Supported forensic tools
 */
export const FORENSIC_TOOLS = ['yara', 'clamav', 'evidence-miner', 'log2timeline'] as const;
export type ForensicToolName = (typeof FORENSIC_TOOLS)[number];

/**
 * Resource profile schema for validation
 */
export const ResourceProfileSchema = z.object({
  /** Base CPU units (1024 = 1 vCPU) */
  baseCpu: z.number().min(256).max(16384),
  /** Base memory in MB */
  baseMemoryMb: z.number().min(512).max(122880),
  /** Additional CPU per 100GB of snapshot */
  cpuPer100Gb: z.number().min(0),
  /** Additional memory per 100GB of snapshot */
  memoryPer100Gb: z.number().min(0),
  /** Maximum CPU units */
  maxCpu: z.number().min(256).max(16384),
  /** Maximum memory in MB */
  maxMemoryMb: z.number().min(512).max(122880),
  /** Base timeout in minutes */
  baseTimeoutMinutes: z.number().min(1),
  /** Additional timeout per GB */
  timeoutPerGbMinutes: z.number().min(0),
  /** Maximum timeout in minutes */
  maxTimeoutMinutes: z.number().min(1),
  /** Whether tool failure should abort workflow */
  critical: z.boolean(),
});

/**
 * Default resource profiles per tool
 * Based on the design document's resource allocation matrix
 */
export const DEFAULT_RESOURCE_PROFILES: Record<ForensicToolName, ToolResourceConfig> = {
  yara: {
    baseCpu: 1024,           // 1 vCPU
    baseMemoryMb: 4096,      // 4 GB
    cpuPer100Gb: 512,        // +0.5 vCPU per 100GB
    memoryPer100Gb: 2048,    // +2 GB per 100GB
    maxCpu: 4096,            // 4 vCPU max
    maxMemoryMb: 16384,      // 16 GB max
    baseTimeoutMinutes: 10,
    timeoutPerGbMinutes: 0.5,
    maxTimeoutMinutes: 60,
    critical: true,
  },
  clamav: {
    baseCpu: 2048,           // 2 vCPU
    baseMemoryMb: 4096,      // 4 GB
    cpuPer100Gb: 512,        // +0.5 vCPU per 100GB
    memoryPer100Gb: 2048,    // +2 GB per 100GB
    maxCpu: 4096,            // 4 vCPU max
    maxMemoryMb: 16384,      // 16 GB max
    baseTimeoutMinutes: 15,
    timeoutPerGbMinutes: 1,
    maxTimeoutMinutes: 120,
    critical: false,         // Optional tool - failures don't abort workflow
  },
  'evidence-miner': {
    baseCpu: 2048,           // 2 vCPU
    baseMemoryMb: 8192,      // 8 GB
    cpuPer100Gb: 1024,       // +1 vCPU per 100GB
    memoryPer100Gb: 4096,    // +4 GB per 100GB
    maxCpu: 8192,            // 8 vCPU max
    maxMemoryMb: 32768,      // 32 GB max
    baseTimeoutMinutes: 20,
    timeoutPerGbMinutes: 1,
    maxTimeoutMinutes: 120,
    critical: true,
  },
  log2timeline: {
    baseCpu: 4096,           // 4 vCPU
    baseMemoryMb: 16384,     // 16 GB
    cpuPer100Gb: 2048,       // +2 vCPU per 100GB
    memoryPer100Gb: 8192,    // +8 GB per 100GB
    maxCpu: 16384,           // 16 vCPU max
    maxMemoryMb: 65536,      // 64 GB max
    baseTimeoutMinutes: 30,
    timeoutPerGbMinutes: 2,
    maxTimeoutMinutes: 240,
    critical: true,
  },
};

/**
 * Calculated resource allocation for a specific task
 */
export interface ResourceAllocation {
  /** CPU units (1024 = 1 vCPU) */
  cpu: number;
  /** Memory in MB */
  memoryMb: number;
  /** Timeout in minutes */
  timeoutMinutes: number;
  /** Timeout in seconds */
  timeoutSeconds: number;
}

/**
 * Calculate resource allocation for a tool based on snapshot size
 *
 * @param tool - Tool name
 * @param snapshotSizeGb - Snapshot size in GB
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns Calculated resource allocation
 */
export function calculateResourceAllocation(
  tool: ForensicToolName,
  snapshotSizeGb: number,
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): ResourceAllocation {
  const config = profiles[tool];
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

  // Round CPU to valid Fargate values (256, 512, 1024, 2048, 4096, 8192, 16384)
  const validCpuValues = [256, 512, 1024, 2048, 4096, 8192, 16384];
  const roundedCpu = validCpuValues.find(v => v >= cpu) ?? validCpuValues[validCpuValues.length - 1];

  return {
    cpu: roundedCpu,
    memoryMb,
    timeoutMinutes,
    timeoutSeconds: timeoutMinutes * 60,
  };
}

/**
 * Calculate resources for all tools for a given snapshot size
 *
 * @param snapshotSizeGb - Snapshot size in GB
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns Map of tool name to resource allocation
 */
export function calculateAllToolResources(
  snapshotSizeGb: number,
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): Record<ForensicToolName, ResourceAllocation> {
  const result: Record<ForensicToolName, ResourceAllocation> = {} as any;

  for (const tool of FORENSIC_TOOLS) {
    result[tool] = calculateResourceAllocation(tool, snapshotSizeGb, profiles);
  }

  return result;
}

/**
 * Check if a tool is critical (failure aborts workflow)
 *
 * @param tool - Tool name
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns Whether the tool is critical
 */
export function isToolCritical(
  tool: ForensicToolName,
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): boolean {
  return profiles[tool]?.critical ?? true;
}

/**
 * Get list of critical tools
 *
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns List of critical tool names
 */
export function getCriticalTools(
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): ForensicToolName[] {
  return FORENSIC_TOOLS.filter(tool => profiles[tool]?.critical);
}

/**
 * Get list of optional (non-critical) tools
 *
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns List of optional tool names
 */
export function getOptionalTools(
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): ForensicToolName[] {
  return FORENSIC_TOOLS.filter(tool => !profiles[tool]?.critical);
}

/**
 * Estimate total resource usage for a case
 *
 * @param snapshotSizeGb - Snapshot size in GB
 * @param profiles - Resource profiles (optional, uses defaults)
 * @returns Estimated resource usage summary
 */
export function estimateTotalResources(
  snapshotSizeGb: number,
  profiles: Record<ForensicToolName, ToolResourceConfig> = DEFAULT_RESOURCE_PROFILES
): {
  totalCpuMinutes: number;
  totalMemoryGbMinutes: number;
  maxConcurrentCpu: number;
  maxConcurrentMemoryMb: number;
  estimatedDurationMinutes: number;
} {
  const allocations = calculateAllToolResources(snapshotSizeGb, profiles);

  let totalCpuMinutes = 0;
  let totalMemoryGbMinutes = 0;
  let maxConcurrentCpu = 0;
  let maxConcurrentMemoryMb = 0;
  let maxTimeout = 0;

  for (const tool of FORENSIC_TOOLS) {
    const alloc = allocations[tool];
    totalCpuMinutes += (alloc.cpu / 1024) * alloc.timeoutMinutes;
    totalMemoryGbMinutes += (alloc.memoryMb / 1024) * alloc.timeoutMinutes;
    maxConcurrentCpu += alloc.cpu;
    maxConcurrentMemoryMb += alloc.memoryMb;
    maxTimeout = Math.max(maxTimeout, alloc.timeoutMinutes);
  }

  return {
    totalCpuMinutes,
    totalMemoryGbMinutes,
    maxConcurrentCpu,
    maxConcurrentMemoryMb,
    estimatedDurationMinutes: maxTimeout, // Parallel execution, so max timeout
  };
}

/**
 * Validate memory is appropriate for CPU allocation
 * Based on AWS Fargate task size combinations
 *
 * @param cpu - CPU units
 * @param memoryMb - Memory in MB
 * @returns Whether the combination is valid
 */
export function isValidFargateTaskSize(cpu: number, memoryMb: number): boolean {
  const validCombinations: Record<number, { min: number; max: number }> = {
    256: { min: 512, max: 2048 },
    512: { min: 1024, max: 4096 },
    1024: { min: 2048, max: 8192 },
    2048: { min: 4096, max: 16384 },
    4096: { min: 8192, max: 30720 },
    8192: { min: 16384, max: 61440 },
    16384: { min: 32768, max: 122880 },
  };

  const limits = validCombinations[cpu];
  if (!limits) {
    return false;
  }

  return memoryMb >= limits.min && memoryMb <= limits.max;
}

/**
 * Adjust memory to be valid for given CPU
 *
 * @param cpu - CPU units
 * @param requestedMemoryMb - Requested memory in MB
 * @returns Valid memory allocation
 */
export function adjustMemoryForCpu(cpu: number, requestedMemoryMb: number): number {
  const validCombinations: Record<number, { min: number; max: number }> = {
    256: { min: 512, max: 2048 },
    512: { min: 1024, max: 4096 },
    1024: { min: 2048, max: 8192 },
    2048: { min: 4096, max: 16384 },
    4096: { min: 8192, max: 30720 },
    8192: { min: 16384, max: 61440 },
    16384: { min: 32768, max: 122880 },
  };

  const limits = validCombinations[cpu];
  if (!limits) {
    throw new Error(`Invalid CPU value: ${cpu}`);
  }

  return Math.max(limits.min, Math.min(requestedMemoryMb, limits.max));
}
