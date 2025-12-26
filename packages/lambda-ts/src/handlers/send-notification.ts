/**
 * Notification handler
 */
import { Handler } from 'aws-lambda';
import {
  createLogger,
  NotificationChannel,
  NotificationPriority,
  Notification,
} from '@snapshot-sleuth/shared';
import { AdapterFactory } from '@snapshot-sleuth/adapters';

const logger = createLogger();

export interface NotificationEvent {
  caseId: string;
  subject: string;
  message: string;
  priority: NotificationPriority;
  channels: {
    channel: NotificationChannel;
    config: Record<string, unknown>;
  }[];
}

export const handler: Handler<NotificationEvent, void> = async (event) => {
  logger.info('Sending notifications', {
    caseId: event.caseId,
    channels: event.channels.map((c) => c.channel),
  });

  try {
    const notification: Omit<Notification, 'id' | 'timestamp'> = {
      channel: NotificationChannel.SLACK, // Will be overridden
      priority: event.priority,
      subject: event.subject,
      message: event.message,
      caseId: event.caseId,
      metadata: {},
    };

    // Send to each configured channel
    for (const channelConfig of event.channels) {
      try {
        const adapter = AdapterFactory.createNotificationAdapter(
          channelConfig.channel,
          channelConfig.config
        );

        await adapter.send({
          ...notification,
          channel: channelConfig.channel,
        });

        logger.info('Notification sent successfully', {
          channel: channelConfig.channel,
        });
      } catch (error) {
        logger.error('Failed to send notification', {
          channel: channelConfig.channel,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue with other channels even if one fails
      }
    }
  } catch (error) {
    logger.error('Failed to send notifications', {
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
};
