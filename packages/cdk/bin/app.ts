#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SnapshotSleuthStack } from '../lib/stacks/snapshot-sleuth-stack';

const app = new cdk.App();

const environment = app.node.tryGetContext('environment') || 'development';
const projectName = app.node.tryGetContext('projectName') || 'snapshot-sleuth';

new SnapshotSleuthStack(app, `${projectName}-${environment}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
  description: 'Snapshot Sleuth - Automated Cloud Forensics and Incident Response',
  tags: {
    Project: projectName,
    Environment: environment,
    ManagedBy: 'CDK',
  },
});

app.synth();
