# Snapshot Sleuth Demo

## Overview

The demo package provides a one-command deployment for testing Snapshot Sleuth with prebuilt scenarios.

## Scenarios

### 1. Malware Detection
Simulates a snapshot containing malicious files detected by ClamAV and YARA.

### 2. Data Exfiltration
Simulates evidence of data being copied to external locations.

### 3. Privilege Escalation
Simulates unauthorized privilege escalation indicators.

### 4. Clean Baseline
A clean snapshot for comparison and baseline testing.

## Deployment

```bash
cd packages/demo
pnpm deploy
```

This will:
1. Create a demo VPC and security groups
2. Launch demo EC2 instances for each scenario
3. Create snapshots
4. Tag with auto-expiry (24 hours by default)
5. Trigger forensic workflows

## Safety Controls

- **Tagging**: All demo resources tagged with `Demo:SnapshotSleuth`
- **TTL**: Auto-expiry after 24 hours
- **Cost Alerts**: Threshold set at $100/month
- **Isolated VPC**: Demo runs in separate VPC

## Configuration

Edit `config.json`:

```json
{
  "ttlHours": 24,
  "costThreshold": 100,
  "region": "us-east-1",
  "autoCleanup": true
}
```

## Cleanup

```bash
pnpm clean
```

Removes all demo resources immediately.

## Cost Estimate

Approximate cost for 24-hour demo:
- EC2 instances (t3.micro): ~$1
- EBS volumes: ~$0.50
- Snapshots: ~$0.50
- Lambda executions: ~$0.10
- **Total**: ~$2-3 per run

## Note

Demo is for testing only. Do not use in production.
