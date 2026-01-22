---
layout: default
title: Home
---

<div class="hero">
  <h1>Snapshot-Sleuth</h1>
  <p class="tagline">Serverless Forensic Automation System</p>
</div>

## Overview

Snapshot-Sleuth is a production-grade automated forensic analysis system for AWS EBS snapshots. It transforms incident response from hours of manual work into minutes of automated processing using event-driven serverless architecture.

<div class="metrics-grid">
  <div class="metric">
    <span class="metric-value">71%</span>
    <span class="metric-label">Faster Processing</span>
  </div>
  <div class="metric">
    <span class="metric-value">150+</span>
    <span class="metric-label">Hours Recovered</span>
  </div>
  <div class="metric">
    <span class="metric-value">100+</span>
    <span class="metric-label">Snapshots Analyzed</span>
  </div>
  <div class="metric">
    <span class="metric-value">16</span>
    <span class="metric-label">CDK Stacks</span>
  </div>
</div>

## Architecture Highlights

- **Event-driven ingestion** via EventBridge and SQS for automatic workflow triggering
- **Hybrid compute model** combining Lambda orchestration with EC2 forensics
- **Multi-tool scanning** with YARA, ClamAV, and custom artifact collectors
- **Infrastructure as Code** using AWS CDK across 20+ regions

## Technical Stack

| Category | Technologies |
|----------|-------------|
| **Languages** | TypeScript, Python, React |
| **AWS Services** | Lambda, Step Functions, EventBridge, EC2, S3, DynamoDB, CloudWatch, X-Ray |
| **Forensic Tools** | YARA, ClamAV, ColdSnap |
| **Infrastructure** | AWS CDK, Turborepo, Bun |

---

<div class="cta-section">
  <h2>Technical Case Study</h2>
  <p>Deep dive into the architecture, implementation patterns, and lessons learned building this system.</p>
  <a href="{{ '/case-study' | relative_url }}" class="cta-button">Read the Case Study</a>
</div>

---

<div class="links-section">
  <a href="https://github.com/{{ site.repository }}" class="link-item">
    <strong>Source Code</strong>
    <span>View on GitHub</span>
  </a>
  <a href="https://github.com/{{ site.repository }}/tree/main/docs" class="link-item">
    <strong>Documentation</strong>
    <span>Architecture & Deployment</span>
  </a>
</div>
