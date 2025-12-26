# Adapter Development Guide

## Overview

The adapter layer provides a pluggable architecture for integrating with various external systems. This guide explains how to develop custom adapters.

## Architecture

Adapters follow a simple interface pattern:

```typescript
interface IAdapter {
  // Implement required methods
  // Return typed results
  // Handle errors gracefully
}
```

## Creating a Custom Case Management Adapter

### 1. Define the Interface

All case management adapters must implement `ICaseManagementAdapter`:

```typescript
import { ICaseManagementAdapter } from '@snapshot-sleuth/adapters';
import { Case, CaseStatus } from '@snapshot-sleuth/shared';

export class CustomCaseManagementAdapter implements ICaseManagementAdapter {
  async createCase(caseData: Omit<Case, 'id' | 'createdAt' | 'updatedAt'>): Promise<Case> {
    // Implementation
  }

  async getCase(caseId: string): Promise<Case | null> {
    // Implementation
  }

  async updateCaseStatus(caseId: string, status: CaseStatus): Promise<Case> {
    // Implementation
  }

  // ... other required methods
}
```

### 2. Register in Factory

Add your adapter to the `AdapterFactory`:

```typescript
// packages/adapters/src/factory/adapter-factory.ts
import { CustomCaseManagementAdapter } from '../providers/custom-case-management';

export class AdapterFactory {
  static createCaseManagementAdapter(
    provider: ProviderType,
    config: Record<string, unknown>
  ): ICaseManagementAdapter {
    switch (provider) {
      // ... existing cases
      case ProviderType.CUSTOM:
        return new CustomCaseManagementAdapter(config as any);
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  }
}
```

## Creating a Custom Notification Adapter

### 1. Implement the Interface

```typescript
import { INotificationAdapter } from '@snapshot-sleuth/adapters';
import { Notification, NotificationChannel } from '@snapshot-sleuth/shared';

export class CustomNotificationAdapter implements INotificationAdapter {
  private config: CustomConfig;

  constructor(config: CustomConfig) {
    this.config = config;
  }

  getChannel(): NotificationChannel {
    return NotificationChannel.WEBHOOK;
  }

  async send(notification: Omit<Notification, 'id' | 'timestamp'>): Promise<void> {
    // Send notification via your service
    await this.customService.sendNotification({
      title: notification.subject,
      body: notification.message,
      priority: notification.priority,
    });
  }

  async validateConfig(): Promise<boolean> {
    // Test connection to your service
    try {
      await this.customService.ping();
      return true;
    } catch {
      return false;
    }
  }
}
```

### 2. Add Configuration Schema

Update the configuration schema in `@snapshot-sleuth/shared`:

```typescript
export interface CustomConfig {
  apiUrl: string;
  apiKey: string;
  timeout?: number;
}
```

## Best Practices

### Error Handling

Always wrap external API calls in try-catch blocks:

```typescript
async getCase(caseId: string): Promise<Case | null> {
  try {
    const response = await this.api.get(`/cases/${caseId}`);
    return this.parseCase(response.data);
  } catch (error) {
    logger.error('Failed to get case', { caseId, error });
    return null;
  }
}
```

### Logging

Use the shared logger for consistent logging:

```typescript
import { createLogger } from '@snapshot-sleuth/shared';

const logger = createLogger({ adapter: 'CustomAdapter' });

logger.info('Creating case', { caseData });
logger.error('Failed to create case', { error });
```

### Configuration Validation

Validate configuration at initialization:

```typescript
constructor(config: CustomConfig) {
  if (!config.apiUrl || !config.apiKey) {
    throw new Error('CustomAdapter requires apiUrl and apiKey');
  }
  this.config = config;
}
```

### Rate Limiting

Implement rate limiting for external APIs:

```typescript
import { retry } from '@snapshot-sleuth/shared';

async makeRequest() {
  return retry(
    async () => await this.api.get('/endpoint'),
    {
      maxAttempts: 3,
      initialDelay: 1000,
      backoffMultiplier: 2,
    }
  );
}
```

## Testing

Create unit tests for your adapter:

```typescript
import { CustomAdapter } from './custom-adapter';

describe('CustomAdapter', () => {
  let adapter: CustomAdapter;

  beforeEach(() => {
    adapter = new CustomAdapter({
      apiUrl: 'https://api.example.com',
      apiKey: 'test-key',
    });
  });

  it('should create a case', async () => {
    const caseData = {
      snapshotId: 'snap-123',
      region: 'us-east-1',
      // ...
    };

    const result = await adapter.createCase(caseData);
    expect(result.id).toBeDefined();
  });
});
```

## Examples

See existing adapters for reference:
- `GitHubCaseManagementAdapter` - Full-featured case management
- `SlackNotificationAdapter` - Simple notification integration
- `EmailNotificationAdapter` - AWS SES integration

## Contributing

When contributing a new adapter:

1. Implement the required interface
2. Add comprehensive tests
3. Update documentation
4. Submit a pull request

For questions, open a discussion on GitHub.
