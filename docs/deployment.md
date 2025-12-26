# Deployment Guide

## Prerequisites

Before deploying Snapshot Sleuth, ensure you have:

- AWS Account with appropriate permissions
- AWS CLI configured (`aws configure`)
- Node.js >= 18.0.0
- pnpm >= 8.0.0
- AWS CDK CLI (`npm install -g aws-cdk`)

## Initial Setup

1. **Clone the repository**:
```bash
git clone https://github.com/Stealinglight/Snapshot-Sleuth.git
cd Snapshot-Sleuth
```

2. **Install dependencies**:
```bash
pnpm install
```

3. **Build all packages**:
```bash
pnpm build
```

## Configuration

Create a `.env` file in the CDK package:

```bash
cd packages/cdk
cat > .env << EOF
ENVIRONMENT=production
AWS_REGION=us-east-1
PROJECT_NAME=snapshot-sleuth
ALARM_EMAIL=security@yourcompany.com

# GitHub Integration
GITHUB_TOKEN=your_github_token
GITHUB_OWNER=your_org
GITHUB_REPO=security-cases

# Slack Integration (optional)
SLACK_WEBHOOK_URL=your_slack_webhook

# Email Notification (optional)
EMAIL_FROM=noreply@yourcompany.com
EMAIL_TO=security-team@yourcompany.com
EOF
```

## CDK Deployment

1. **Bootstrap CDK** (first time only):
```bash
cd packages/cdk
pnpm cdk bootstrap
```

2. **Review changes**:
```bash
pnpm cdk diff
```

3. **Deploy the stack**:
```bash
pnpm cdk deploy
```

4. **Note the outputs**:
```
Outputs:
snapshot-sleuth-production.StateMachineArn = arn:aws:states:...
snapshot-sleuth-production.EvidenceBucketName = snapshot-sleuth-evidence-production
snapshot-sleuth-production.DashboardUrl = https://console.aws.amazon.com/...
```

## Frontend Deployment

### Option 1: AWS Amplify

1. Connect your GitHub repository to AWS Amplify
2. Configure build settings:
```yaml
version: 1
frontend:
  phases:
    preBuild:
      commands:
        - npm install -g pnpm@8
        - pnpm install
    build:
      commands:
        - cd packages/frontend
        - pnpm build
  artifacts:
    baseDirectory: packages/frontend/dist
    files:
      - '**/*'
  cache:
    paths:
      - node_modules/**/*
```

### Option 2: S3 + CloudFront

```bash
cd packages/frontend
pnpm build
aws s3 sync dist/ s3://your-frontend-bucket
```

## Post-Deployment

1. **Verify the deployment**:
```bash
aws stepfunctions list-state-machines
```

2. **Test with a sample snapshot**:
```bash
aws stepfunctions start-execution \
  --state-machine-arn YOUR_STATE_MACHINE_ARN \
  --input '{"snapshotId":"snap-xxxxx","region":"us-east-1"}'
```

3. **Monitor the execution**:
- Check CloudWatch Dashboard
- Review CloudWatch Logs
- Check GitHub Issues for case creation

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure your AWS credentials have sufficient permissions
2. **Stack Already Exists**: Delete the existing stack or use a different name
3. **Resource Limits**: Check AWS service quotas

### Logs

- CloudWatch Logs: `/aws/snapshot-sleuth/{environment}`
- CloudTrail: Check S3 logs bucket
- Lambda Logs: Each function has its own log group

## Cleanup

To remove all resources:

```bash
cd packages/cdk
pnpm cdk destroy
```

**Note**: S3 buckets with versioning enabled will need manual deletion.
