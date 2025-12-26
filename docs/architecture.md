# Architecture Documentation

## System Overview

Snapshot Sleuth is a cloud-native forensics and incident-response platform built on AWS, designed to automate the analysis of EBS snapshots for security investigations.

## Core Components

### 1. Workflow Orchestration

The system uses AWS Step Functions to orchestrate the forensic workflow:

```
Snapshot Event → Validation → Preparation → Analysis → Upload → Notification → Cleanup
```

Each step is implemented as a Lambda function or parallel execution of multiple tools.

### 2. Forensic Tool Pipeline

Four integrated forensic tools run in parallel during analysis:

- **YARA**: Rule-based pattern matching and detection
- **ClamAV**: Malware scanning and virus detection
- **Wolverine**: Artifact extraction and classification
- **Log2Timeline**: Timeline generation for incident reconstruction

### 3. Storage Architecture

```
S3 Buckets:
├── Evidence Bucket    # Encrypted storage for forensic evidence
├── Artifacts Bucket   # Tool outputs and analysis results
└── Logs Bucket        # CloudTrail and application logs
```

### 4. Adapter Layer

The pluggable adapter layer provides vendor-neutral integration:

```typescript
AdapterFactory
├── Case Management (GitHub, Jira, Linear, Custom)
├── Ticketing (GitHub, Jira, Zendesk, Custom)
└── Notifications (Slack, Email, Webhook)
```

### 5. Frontend Application

Modern React application with:
- Real-time case monitoring
- Evidence browser
- Workflow status tracking
- Dark mode support

## Security Architecture

- KMS encryption for data at rest
- IAM roles with least-privilege access
- VPC isolation for analysis environments
- CloudTrail audit logging
- Security group restrictions

## Monitoring & Observability

- CloudWatch Dashboards for metrics
- Custom alarms for failures
- Structured logging with correlation IDs
- Distributed tracing with X-Ray

## Scalability

- Parallel tool execution
- Auto-scaling Lambda functions
- S3 for unlimited storage
- DynamoDB for case metadata (future)

## Technology Stack

- **Infrastructure**: AWS CDK (TypeScript)
- **Backend**: Lambda (TypeScript, Python)
- **Frontend**: React + Vite + TypeScript
- **Monorepo**: pnpm + Turborepo
- **CI/CD**: GitHub Actions
