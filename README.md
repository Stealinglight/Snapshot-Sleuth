# Snapshot Sleuth

> Automated Cloud Forensics and Incident Response Workflow

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)
![AWS CDK](https://img.shields.io/badge/AWS%20CDK-2.125-orange.svg)

## Overview

Snapshot Sleuth is a comprehensive cloud forensics and incident-response workflow designed to help security teams investigate EBS snapshot-based evidence quickly and consistently. The system orchestrates analysis, runs multiple forensic tools, and publishes evidence and results into durable storage with clear case tracking and notifications.

## Key Features

### 🔍 Forensic Tool Pipeline
- **YARA** - Rule-based detection and pattern matching
- **ClamAV** - Malware scanning and virus detection
- **EvidenceMiner** - Artifact extraction and classification
- **Log2Timeline** - Timeline generation and analysis

### 🔌 Pluggable Adapter Layer
- **Case Management** - GitHub Issues, Jira, Linear (extensible)
- **Ticketing** - GitHub Issues, Jira, Zendesk (extensible)
- **Notifications** - Slack, Email, Webhook (extensible)

### 📊 Monitoring & Observability
- CloudWatch dashboards and metrics
- CloudTrail audit logging
- Real-time status updates
- Custom alarms and alerts

### 🎯 Modern Frontend
- Case list and detail views
- Workflow monitoring dashboard
- Evidence browser with preview
- Dark mode support
- Responsive design

## Architecture

The project is organized as a TypeScript monorepo using pnpm workspaces and Turborepo:

```
packages/
├── shared/        # Shared types, utilities, and configuration
├── adapters/      # Pluggable adapter layer for integrations
├── cdk/           # AWS CDK infrastructure code
├── lambda-ts/     # TypeScript Lambda functions
├── lambda-py/     # Python Lambda functions (forensic tools)
├── frontend/      # React frontend application
└── demo/          # Demo environment and scenarios
```

## Getting Started

### Prerequisites

- Node.js >= 18.0.0
- pnpm >= 8.0.0
- AWS CLI configured
- AWS CDK CLI installed

### Installation

```bash
# Clone the repository
git clone https://github.com/Stealinglight/Snapshot-Sleuth.git
cd Snapshot-Sleuth

# Install dependencies
pnpm install

# Build all packages
pnpm build
```

### Configuration

Create a configuration file based on your environment:

```typescript
{
  "environment": "development",
  "projectName": "snapshot-sleuth",
  "aws": {
    "region": "us-east-1",
    "s3BucketPrefix": "snapshot-sleuth"
  },
  "adapters": {
    "caseManagement": {
      "provider": "GITHUB",
      "config": {
        "token": "YOUR_GITHUB_TOKEN",
        "owner": "YOUR_ORG",
        "repo": "YOUR_REPO"
      }
    },
    "notifications": [
      {
        "channel": "SLACK",
        "enabled": true,
        "config": {
          "webhookUrl": "YOUR_SLACK_WEBHOOK"
        }
      }
    ]
  }
}
```

### Deployment

```bash
# Deploy CDK stack
cd packages/cdk
pnpm cdk deploy
```

### Development

```bash
# Start frontend development server
cd packages/frontend
pnpm dev

# Watch for changes in shared packages
cd packages/shared
pnpm build --watch
```

## Workflow

1. **Snapshot Event** - EBS snapshot is shared or identified for investigation
2. **Validation** - Snapshot is validated and accessible
3. **Preparation** - Snapshot is copied to analysis region if needed
4. **Provisioning** - Isolated analysis environment is created
5. **Analysis** - Forensic tools run in parallel
6. **Evidence Upload** - Results and artifacts uploaded to S3
7. **Notification** - Stakeholders notified of completion
8. **Cleanup** - Analysis environment cleaned up

## Documentation

- [Architecture Documentation](./docs/architecture.md)
- [Deployment Guide](./docs/deployment.md)
- [Configuration Options](./docs/configuration.md)
- [Adapter Development](./docs/adapters.md)
- [Troubleshooting](./docs/troubleshooting.md)
- [Security Best Practices](./docs/security.md)

## Demo

The demo package provides one-command deployment with prebuilt scenarios:

- Malware detection scenario
- Data exfiltration scenario
- Privilege escalation scenario
- Clean baseline scenario

Safety controls include tagging, TTL auto-expiry, and cost estimation/alerts.

## Contributing

Contributions are welcome! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Security

For security concerns, please see our [Security Policy](./SECURITY.md).

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issue Tracker](https://github.com/Stealinglight/Snapshot-Sleuth/issues)
- 💬 [Discussions](https://github.com/Stealinglight/Snapshot-Sleuth/discussions) 
