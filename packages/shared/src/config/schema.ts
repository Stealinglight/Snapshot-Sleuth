/**
 * Configuration schema and validation using Zod
 */
import { z } from 'zod';
import { ProviderType, NotificationChannel } from '../types';

/**
 * AWS configuration schema
 */
export const AwsConfigSchema = z.object({
  region: z.string().default('us-east-1'),
  accountId: z.string().optional(),
  s3BucketPrefix: z.string().default('snapshot-sleuth'),
  kmsKeyId: z.string().optional(),
});

export type AwsConfig = z.infer<typeof AwsConfigSchema>;

/**
 * Adapter configuration schema
 */
export const AdapterConfigSchema = z.object({
  caseManagement: z.object({
    provider: z.nativeEnum(ProviderType),
    config: z.record(z.unknown()),
  }),
  ticketing: z.object({
    provider: z.nativeEnum(ProviderType),
    config: z.record(z.unknown()),
  }),
  notifications: z.array(
    z.object({
      channel: z.nativeEnum(NotificationChannel),
      enabled: z.boolean().default(true),
      config: z.record(z.unknown()),
    })
  ),
});

export type AdapterConfig = z.infer<typeof AdapterConfigSchema>;

/**
 * Forensic tool configuration schema
 */
export const ForensicToolConfigSchema = z.object({
  yara: z
    .object({
      enabled: z.boolean().default(true),
      rulesS3Bucket: z.string().optional(),
      rulesS3Key: z.string().optional(),
      timeout: z.number().default(3600),
    })
    .optional(),
  clamav: z
    .object({
      enabled: z.boolean().default(true),
      timeout: z.number().default(3600),
    })
    .optional(),
  wolverine: z
    .object({
      enabled: z.boolean().default(true),
      timeout: z.number().default(7200),
    })
    .optional(),
  log2timeline: z
    .object({
      enabled: z.boolean().default(true),
      timeout: z.number().default(7200),
    })
    .optional(),
});

export type ForensicToolConfig = z.infer<typeof ForensicToolConfigSchema>;

/**
 * Monitoring configuration schema
 */
export const MonitoringConfigSchema = z.object({
  enableCloudWatch: z.boolean().default(true),
  enableCloudTrail: z.boolean().default(true),
  createDashboard: z.boolean().default(true),
  alarmEmail: z.string().email().optional(),
  logRetentionDays: z.number().default(30),
});

export type MonitoringConfig = z.infer<typeof MonitoringConfigSchema>;

/**
 * Demo configuration schema
 */
export const DemoConfigSchema = z.object({
  enabled: z.boolean().default(false),
  autoExpiry: z.boolean().default(true),
  ttlHours: z.number().default(24),
  costAlertThreshold: z.number().default(100),
});

export type DemoConfig = z.infer<typeof DemoConfigSchema>;

/**
 * Main application configuration schema
 */
export const AppConfigSchema = z.object({
  environment: z.enum(['development', 'staging', 'production']).default('development'),
  projectName: z.string().default('snapshot-sleuth'),
  aws: AwsConfigSchema,
  adapters: AdapterConfigSchema,
  forensicTools: ForensicToolConfigSchema,
  monitoring: MonitoringConfigSchema,
  demo: DemoConfigSchema.optional(),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;

/**
 * Validate configuration
 */
export function validateConfig(config: unknown): AppConfig {
  return AppConfigSchema.parse(config);
}

/**
 * Load configuration from environment variables
 */
export function loadConfigFromEnv(): Partial<AppConfig> {
  return {
    environment: (process.env.ENVIRONMENT as any) || 'development',
    projectName: process.env.PROJECT_NAME || 'snapshot-sleuth',
    aws: {
      region: process.env.AWS_REGION || 'us-east-1',
      accountId: process.env.AWS_ACCOUNT_ID,
      s3BucketPrefix: process.env.S3_BUCKET_PREFIX || 'snapshot-sleuth',
      kmsKeyId: process.env.KMS_KEY_ID,
    },
  };
}
