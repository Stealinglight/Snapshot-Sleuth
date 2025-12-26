/**
 * Slack notification adapter
 */
import axios from 'axios';
import {
  Notification,
  NotificationChannel,
  SlackConfig,
  formatTimestamp,
} from '@snapshot-sleuth/shared';
import { INotificationAdapter } from '../interfaces';

export class SlackNotificationAdapter implements INotificationAdapter {
  private config: SlackConfig;

  constructor(config: SlackConfig) {
    this.config = config;
  }

  getChannel(): NotificationChannel {
    return NotificationChannel.SLACK;
  }

  async send(notification: Omit<Notification, 'id' | 'timestamp'>): Promise<void> {
    const color = this.getColorForPriority(notification.priority);
    const payload = {
      channel: this.config.channel,
      username: this.config.username || 'Snapshot Sleuth',
      icon_emoji: this.config.iconEmoji || ':detective:',
      attachments: [
        {
          color,
          title: notification.subject,
          text: notification.message,
          fields: [
            {
              title: 'Priority',
              value: notification.priority,
              short: true,
            },
            ...(notification.caseId
              ? [
                  {
                    title: 'Case ID',
                    value: notification.caseId,
                    short: true,
                  },
                ]
              : []),
          ],
          footer: 'Snapshot Sleuth',
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    await axios.post(this.config.webhookUrl, payload);
  }

  async validateConfig(): Promise<boolean> {
    try {
      await axios.post(this.config.webhookUrl, {
        text: 'Configuration test from Snapshot Sleuth',
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  private getColorForPriority(priority: string): string {
    switch (priority) {
      case 'URGENT':
        return 'danger';
      case 'HIGH':
        return 'warning';
      case 'NORMAL':
        return 'good';
      case 'LOW':
        return '#439FE0';
      default:
        return '#808080';
    }
  }
}
