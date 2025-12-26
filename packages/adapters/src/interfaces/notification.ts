/**
 * Abstract interface for notification providers
 */
import { Notification, NotificationChannel } from '@snapshot-sleuth/shared';

export interface INotificationAdapter {
  /**
   * Get the channel this adapter supports
   */
  getChannel(): NotificationChannel;

  /**
   * Send a notification
   */
  send(notification: Omit<Notification, 'id' | 'timestamp'>): Promise<void>;

  /**
   * Validate configuration
   */
  validateConfig(): Promise<boolean>;
}
