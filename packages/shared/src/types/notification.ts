/**
 * Notification types and interfaces
 */

/**
 * Notification channel types
 */
export enum NotificationChannel {
  SLACK = 'SLACK',
  EMAIL = 'EMAIL',
  WEBHOOK = 'WEBHOOK',
}

/**
 * Notification priority
 */
export enum NotificationPriority {
  URGENT = 'URGENT',
  HIGH = 'HIGH',
  NORMAL = 'NORMAL',
  LOW = 'LOW',
}

/**
 * Notification payload
 */
export interface Notification {
  id: string;
  channel: NotificationChannel;
  priority: NotificationPriority;
  subject: string;
  message: string;
  caseId?: string;
  metadata: Record<string, unknown>;
  timestamp: string;
}

/**
 * Slack notification configuration
 */
export interface SlackConfig {
  webhookUrl: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

/**
 * Email notification configuration
 */
export interface EmailConfig {
  fromAddress: string;
  toAddresses: string[];
  ccAddresses?: string[];
  sesRegion?: string;
}

/**
 * Webhook notification configuration
 */
export interface WebhookConfig {
  url: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT';
}
