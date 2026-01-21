# Quick Start Guide

Get Snapshot Sleuth up and running in minutes.

## Prerequisites

Ensure you have:
- Node.js 18+ installed
- Bun 1.0+ installed (`curl -fsSL https://bun.sh/install | bash`)
- AWS CLI configured with credentials
- AWS CDK CLI installed (`npm install -g aws-cdk`)

## 1. Clone and Install

```bash
git clone https://github.com/Stealinglight/Snapshot-Sleuth.git
cd Snapshot-Sleuth
bun install
```

## 2. Configure

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
# Edit .env with your configuration
```

At minimum, set:
- `GITHUB_TOKEN` - Personal access token with `repo` scope
- `GITHUB_OWNER` - Your GitHub organization
- `GITHUB_REPO` - Repository for case management

## 3. Build

Build all packages:

```bash
bun run build
```

## 4. Deploy Infrastructure

Bootstrap CDK (first time only):

```bash
cd packages/cdk
bun run cdk bootstrap
```

Deploy the stack:

```bash
bun run cdk deploy
```

Note the outputs, especially the State Machine ARN.

## 5. Test the Workflow

Start a forensic analysis by executing the state machine:

```bash
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:us-east-1:ACCOUNT:stateMachine:snapshot-sleuth-development-workflow \
  --input '{
    "snapshotId": "snap-0123456789abcdef0",
    "region": "us-east-1",
    "caseId": "CASE-001"
  }'
```

## 6. Monitor Progress

View the execution in:
- AWS Step Functions Console
- CloudWatch Dashboard (URL from deployment outputs)
- GitHub Issues (new issue will be created)

## 7. View Results

- **Frontend**: Deploy the React app (see deployment guide)
- **GitHub**: Check the created issue for case details
- **S3**: Evidence stored in the evidence bucket

## Next Steps

- **Configure adapters**: Set up Slack or email notifications
- **Add YARA rules**: Upload custom rules to S3
- **Customize workflow**: Modify the Step Functions definition
- **Set up demo**: Try the demo scenarios

## Common Commands

```bash
# Build all packages
bun run build

# Lint code
bun run lint

# Format code
bun run format

# Run frontend locally
cd packages/frontend && bun run dev

# Deploy CDK changes
cd packages/cdk && bun run cdk deploy

# View CDK diff
cd packages/cdk && bun run cdk diff

# Destroy infrastructure
cd packages/cdk && bun run cdk destroy
```

## Troubleshooting

If you encounter issues, see the [Troubleshooting Guide](./docs/troubleshooting.md).

Common fixes:
- Clear caches: `rm -rf node_modules && bun install`
- Rebuild: `bun run clean && bun run build`
- Check AWS credentials: `aws sts get-caller-identity`

## What's Next?

- Read the [Architecture Documentation](./docs/architecture.md)
- Learn about [Adapter Development](./docs/adapters.md)
- Review [Security Best Practices](./SECURITY.md)
- Check out the [Contributing Guide](./CONTRIBUTING.md)

## Getting Help

- 📖 [Full Documentation](./docs/)
- 🐛 [Report Issues](https://github.com/Stealinglight/Snapshot-Sleuth/issues)
- 💬 [Discussions](https://github.com/Stealinglight/Snapshot-Sleuth/discussions)
