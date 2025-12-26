# Configuration Options

## Environment Variables

Snapshot Sleuth can be configured using environment variables or configuration files.

### Core Configuration

```bash
# Environment
ENVIRONMENT=development|staging|production

# Project Settings
PROJECT_NAME=snapshot-sleuth
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=123456789012

# S3 Configuration
S3_BUCKET_PREFIX=snapshot-sleuth
```

### Adapter Configuration

#### GitHub Issues

```bash
GITHUB_TOKEN=ghp_xxxxxxxxxxxxx
GITHUB_OWNER=your-organization
GITHUB_REPO=security-cases
```

#### Slack Notifications

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
SLACK_CHANNEL=#security-alerts
```

#### Email Notifications

```bash
EMAIL_FROM=noreply@yourcompany.com
EMAIL_TO=security@yourcompany.com,soc@yourcompany.com
SES_REGION=us-east-1
```

### Forensic Tools

```bash
# YARA
YARA_ENABLED=true
YARA_RULES_S3_BUCKET=your-yara-rules-bucket
YARA_RULES_S3_KEY=rules/index.yar
YARA_TIMEOUT=3600

# ClamAV
CLAMAV_ENABLED=true
CLAMAV_TIMEOUT=3600

# Wolverine
WOLVERINE_ENABLED=true
WOLVERINE_TIMEOUT=7200

# Log2Timeline
LOG2TIMELINE_ENABLED=true
LOG2TIMELINE_TIMEOUT=7200
```

### Monitoring

```bash
CLOUDWATCH_ENABLED=true
CLOUDTRAIL_ENABLED=true
DASHBOARD_ENABLED=true
ALARM_EMAIL=alerts@yourcompany.com
LOG_RETENTION_DAYS=30
```

## Configuration File

Create `config.json` in the project root:

```json
{
  "environment": "production",
  "projectName": "snapshot-sleuth",
  "aws": {
    "region": "us-east-1",
    "accountId": "123456789012",
    "s3BucketPrefix": "snapshot-sleuth",
    "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/xxxxx"
  },
  "adapters": {
    "caseManagement": {
      "provider": "GITHUB",
      "config": {
        "token": "${GITHUB_TOKEN}",
        "owner": "your-org",
        "repo": "security-cases"
      }
    },
    "ticketing": {
      "provider": "GITHUB",
      "config": {
        "token": "${GITHUB_TOKEN}",
        "owner": "your-org",
        "repo": "security-tickets"
      }
    },
    "notifications": [
      {
        "channel": "SLACK",
        "enabled": true,
        "config": {
          "webhookUrl": "${SLACK_WEBHOOK_URL}",
          "channel": "#security-alerts"
        }
      },
      {
        "channel": "EMAIL",
        "enabled": true,
        "config": {
          "fromAddress": "noreply@yourcompany.com",
          "toAddresses": ["security@yourcompany.com"]
        }
      }
    ]
  },
  "forensicTools": {
    "yara": {
      "enabled": true,
      "rulesS3Bucket": "your-yara-rules",
      "rulesS3Key": "rules/index.yar",
      "timeout": 3600
    },
    "clamav": {
      "enabled": true,
      "timeout": 3600
    },
    "wolverine": {
      "enabled": true,
      "timeout": 7200
    },
    "log2timeline": {
      "enabled": true,
      "timeout": 7200
    }
  },
  "monitoring": {
    "enableCloudWatch": true,
    "enableCloudTrail": true,
    "createDashboard": true,
    "alarmEmail": "alerts@yourcompany.com",
    "logRetentionDays": 30
  }
}
```

## Provider-Specific Configuration

### Jira (Future)

```json
{
  "caseManagement": {
    "provider": "JIRA",
    "config": {
      "host": "yourcompany.atlassian.net",
      "email": "automation@yourcompany.com",
      "apiToken": "your-api-token",
      "projectKey": "SEC"
    }
  }
}
```

### Linear (Future)

```json
{
  "caseManagement": {
    "provider": "LINEAR",
    "config": {
      "apiKey": "lin_api_xxxxx",
      "teamId": "team-id"
    }
  }
}
```

## Validation

Configuration is validated at startup using Zod schemas. Invalid configuration will cause the application to fail with descriptive error messages.

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use environment variables** for sensitive data
3. **Rotate credentials** regularly
4. **Use AWS Secrets Manager** for production secrets
5. **Enable KMS encryption** for S3 buckets
6. **Follow least-privilege** IAM policies

## Example: Using AWS Secrets Manager

```typescript
import { SecretsManager } from '@aws-sdk/client-secrets-manager';

const secretsManager = new SecretsManager({ region: 'us-east-1' });

const secret = await secretsManager.getSecretValue({
  SecretId: 'snapshot-sleuth/github-token',
});

const config = {
  adapters: {
    caseManagement: {
      provider: 'GITHUB',
      config: {
        token: JSON.parse(secret.SecretString!).token,
        // ...
      },
    },
  },
};
```
