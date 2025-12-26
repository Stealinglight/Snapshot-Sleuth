/**
 * Factory for creating adapter instances based on configuration
 */
import { ProviderType, NotificationChannel } from '@snapshot-sleuth/shared';
import {
  ICaseManagementAdapter,
  ITicketingAdapter,
  INotificationAdapter,
} from '../interfaces';
import {
  GitHubCaseManagementAdapter,
  GitHubTicketingAdapter,
  SlackNotificationAdapter,
  EmailNotificationAdapter,
} from '../providers';

export class AdapterFactory {
  /**
   * Create a case management adapter
   */
  static createCaseManagementAdapter(
    provider: ProviderType,
    config: Record<string, unknown>
  ): ICaseManagementAdapter {
    switch (provider) {
      case ProviderType.GITHUB:
        return new GitHubCaseManagementAdapter(config as any);
      case ProviderType.JIRA:
        throw new Error('Jira case management adapter not yet implemented');
      case ProviderType.LINEAR:
        throw new Error('Linear case management adapter not yet implemented');
      default:
        throw new Error(`Unsupported case management provider: ${provider}`);
    }
  }

  /**
   * Create a ticketing adapter
   */
  static createTicketingAdapter(
    provider: ProviderType,
    config: Record<string, unknown>
  ): ITicketingAdapter {
    switch (provider) {
      case ProviderType.GITHUB:
        return new GitHubTicketingAdapter(config as any);
      case ProviderType.JIRA:
        throw new Error('Jira ticketing adapter not yet implemented');
      case ProviderType.LINEAR:
        throw new Error('Linear ticketing adapter not yet implemented');
      case ProviderType.ZENDESK:
        throw new Error('Zendesk ticketing adapter not yet implemented');
      default:
        throw new Error(`Unsupported ticketing provider: ${provider}`);
    }
  }

  /**
   * Create a notification adapter
   */
  static createNotificationAdapter(
    channel: NotificationChannel,
    config: Record<string, unknown>
  ): INotificationAdapter {
    switch (channel) {
      case NotificationChannel.SLACK:
        return new SlackNotificationAdapter(config as any);
      case NotificationChannel.EMAIL:
        return new EmailNotificationAdapter(config as any);
      case NotificationChannel.WEBHOOK:
        throw new Error('Webhook notification adapter not yet implemented');
      default:
        throw new Error(`Unsupported notification channel: ${channel}`);
    }
  }
}
