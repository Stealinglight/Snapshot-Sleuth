---
layout: default
title: Performance Metrics
permalink: /metrics/
description: Detailed performance metrics and benchmarks from the Snapshot-Sleuth forensic automation system.
---

# Snapshot-Sleuth Performance Metrics

## Processing Time Comparison: Legacy vs. Automated

| Snapshot Size | Legacy Manual (avg) | Automated System | Improvement | Time Saved |
|---------------|---------------------|------------------|-------------|------------|
| 8 GB | ~35 minutes | ~10 minutes | 71% | 25 min |
| 50 GB | ~90 minutes | ~25 minutes | 72% | 65 min |
| 100 GB | ~2.5 hours | ~45 minutes | 70% | 1.75 hr |
| 500 GB | ~6 hours | ~1.5 hours | 75% | 4.5 hr |
| 1 TB | ~10 hours | ~2.5 hours | 75% | 7.5 hr |
| 2 TB | ~16 hours | ~4.5 hours | 72% | 11.5 hr |
| 5 TB | ~24+ hours | ~8 hours | 67% | 16+ hr |

**Average Improvement: 71%**

## System Impact Metrics

| Metric | Value | Context |
|--------|-------|---------|
| Total Snapshots Processed | 100+ | Since system launch |
| Incidents Supported | 50+ | Security investigations |
| Team Adoption Rate | 90% | Active users on security team |
| Root Cause Identification | 65% | Cases where automation identified root cause |
| Total Time Saved | 150+ hours | Cumulative analyst time recovered |
| Manual Steps Eliminated | 12 | Per-snapshot processing tasks |

## Codebase Metrics

| Component | Count | Technology |
|-----------|-------|------------|
| Total Lines of Code | ~25,000 | TypeScript, Python, React |
| Infrastructure Stacks | 16 | AWS CDK |
| Lambda Functions | 30+ | TypeScript (21), Python (9) |
| CloudWatch Dashboards | 8 | Specialized monitoring |
| AWS Regions Deployed | 20+ | Commercial, GovCloud, China |
| Forensic Tools Integrated | 4 | YARA, ClamAV, Artifact Collector, Timeline Generator |

## Tool Execution Performance

| Tool | Average Runtime | Files Processed | Detection Type |
|------|-----------------|-----------------|----------------|
| YARA Scanner | 15-45 min | Entire filesystem | Pattern matching |
| ClamAV Scanner | 20-60 min | Entire filesystem | Malware signatures |
| Artifact Collector | 5-15 min | Key locations | IOC extraction |
| Timeline Generator | 30-90 min | System artifacts | Temporal analysis |

## Resource Efficiency

| Resource | Configuration | Cost Optimization |
|----------|---------------|-------------------|
| EC2 Instance Type | m7g.4xlarge (Graviton) | 40% cost reduction vs x86 |
| Lambda Memory | 10 GB | Optimized for snapshot handling |
| S3 Storage Class | Intelligent Tiering | Auto-transitions to Glacier |
| Evidence Retention | 365 days | Lifecycle policies |

## Availability & Reliability

| Metric | Target | Achieved |
|--------|--------|----------|
| Workflow Success Rate | 95% | 97% |
| Average Latency to Start | < 5 min | 2.3 min |
| Dashboard Availability | 99.9% | 99.95% |
| Test Coverage (Canary) | Hourly | Hourly |

## Key Performance Indicators (KPIs)

<div class="kpi-grid">
  <div class="kpi-card">
    <div class="kpi-value">71%</div>
    <div class="kpi-label">Faster Processing</div>
    <div class="kpi-desc">Processing Time Reduction</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-value">150+</div>
    <div class="kpi-label">Hours Saved</div>
    <div class="kpi-desc">Cumulative Analyst Time</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-value">90%</div>
    <div class="kpi-label">Adoption</div>
    <div class="kpi-desc">Team Utilization Rate</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-value">65%</div>
    <div class="kpi-label">Root Cause</div>
    <div class="kpi-desc">Automated Identification</div>
  </div>
</div>

## Processing Time by Snapshot Size

The chart below illustrates the dramatic reduction in processing time achieved through automation:

```
Processing Time (hours)
│
24 ├─────────────────────────────────────────────────────────── ▓▓▓▓▓▓ Legacy (5TB)
   │
16 ├───────────────────────────────────────────── ▓▓▓▓▓▓ Legacy (2TB)
   │
10 ├─────────────────────────────────── ▓▓▓▓▓▓ Legacy (1TB)
   │                                              ████████ Automated (5TB)
 8 ├────────────────────────────────────
   │
 6 ├──────────────────────────── ▓▓▓▓▓▓ Legacy (500GB)
   │
 4 ├──────────────────                   ████████ Automated (2TB)
   │
 2 ├───────── ▓▓▓▓▓▓ Legacy (100GB)    ████████ Automated (1TB)
   │                        ████████ Automated (500GB)
 1 ├────                  ████████ Automated (100GB)
   │     ▓▓▓▓ Legacy (8GB)
 0 └──████────────────────────────────────────────────────────────
       8GB    50GB   100GB  500GB   1TB    2TB    5TB
                        Snapshot Size

  ▓▓▓▓ Legacy Manual    ████ Automated System
```

## Architectural Impact on Performance

### Parallel Execution Benefits

The move from serial to parallel tool execution accounts for the majority of time savings:

| Approach | 1TB Snapshot | Tool Execution |
|----------|--------------|----------------|
| Serial (Legacy) | 10 hours | YARA → ClamAV → Artifacts → Timeline |
| Parallel (Automated) | 2.5 hours | All tools run simultaneously |

### Compute Optimization

Graviton ARM64 instances provide:
- **40% better price-performance** vs comparable x86 instances
- **Consistent performance** for I/O-intensive forensic operations
- **Lower power consumption** for sustained workloads

### Regional Processing Benefits

Processing evidence in-region eliminates:
- Cross-region data transfer latency
- Data sovereignty compliance issues
- Network bandwidth bottlenecks
