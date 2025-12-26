/**
 * Email notification adapter (using AWS SES)
 */
import {
  Notification,
  NotificationChannel,
  EmailConfig,
  formatTimestamp,
} from '@snapshot-sleuth/shared';
import { INotificationAdapter } from '../interfaces';

export class EmailNotificationAdapter implements INotificationAdapter {
  private config: EmailConfig;

  constructor(config: EmailConfig) {
    this.config = config;
  }

  getChannel(): NotificationChannel {
    return NotificationChannel.EMAIL;
  }

  async send(notification: Omit<Notification, 'id' | 'timestamp'>): Promise<void> {
    // This would typically use AWS SES SDK
    // For now, we'll create a placeholder implementation
    const emailBody = this.formatEmailBody(notification);

    console.log('Sending email notification:', {
      from: this.config.fromAddress,
      to: this.config.toAddresses,
      subject: notification.subject,
      body: emailBody,
    });

    // TODO: Implement actual AWS SES integration
    // const ses = new SESClient({ region: this.config.sesRegion || 'us-east-1' });
    // await ses.send(new SendEmailCommand({ ... }));
  }

  async validateConfig(): Promise<boolean> {
    // Validate email addresses format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(this.config.fromAddress)) {
      return false;
    }

    for (const email of this.config.toAddresses) {
      if (!emailRegex.test(email)) {
        return false;
      }
    }

    return true;
  }

  private formatEmailBody(notification: Omit<Notification, 'id' | 'timestamp'>): string {
    let body = `
Priority: ${notification.priority}

${notification.message}
`;

    if (notification.caseId) {
      body += `\nCase ID: ${notification.caseId}`;
    }

    if (Object.keys(notification.metadata).length > 0) {
      body += `\n\nMetadata:\n${JSON.stringify(notification.metadata, null, 2)}`;
    }

    body += `\n\n---\nSent by Snapshot Sleuth at ${new Date().toISOString()}`;

    return body;
  }
}
