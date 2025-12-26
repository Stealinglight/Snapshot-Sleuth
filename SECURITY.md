# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to security@yourcompany.com.

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

## Security Best Practices

When deploying Snapshot Sleuth:

### AWS Security

1. **Enable encryption at rest** for all S3 buckets using KMS
2. **Use IAM roles** with least-privilege permissions
3. **Enable CloudTrail** for audit logging
4. **Use VPC endpoints** for private communication
5. **Enable MFA** for AWS account access

### Application Security

1. **Rotate credentials** regularly (GitHub tokens, API keys, etc.)
2. **Use AWS Secrets Manager** for sensitive configuration
3. **Enable SSL/TLS** for all external communications
4. **Validate all inputs** from external sources
5. **Scan dependencies** for known vulnerabilities

### Network Security

1. **Isolate analysis environments** in dedicated VPCs
2. **Use security groups** to restrict network access
3. **Enable VPC Flow Logs** for network monitoring
4. **Use private subnets** for Lambda functions
5. **Implement network ACLs** for defense in depth

### Data Security

1. **Encrypt evidence** before uploading to S3
2. **Use versioning** on S3 buckets to prevent data loss
3. **Implement lifecycle policies** for data retention
4. **Enable access logging** on S3 buckets
5. **Use signed URLs** for temporary access

### Operational Security

1. **Monitor CloudWatch** for suspicious activity
2. **Set up alarms** for security events
3. **Review audit logs** regularly
4. **Keep dependencies updated** with security patches
5. **Perform regular security assessments**

## Known Security Considerations

### Snapshot Access

- Ensure proper IAM permissions are in place before sharing snapshots
- Snapshots may contain sensitive data - handle with appropriate controls
- Always use KMS encryption for snapshots containing regulated data

### Lambda Execution

- Lambda functions run with specific IAM roles - review regularly
- Cold starts may introduce timing vulnerabilities
- Monitor Lambda invocation patterns for anomalies

### External Integrations

- GitHub tokens provide access to repositories - rotate regularly
- Slack webhooks can be intercepted - use HTTPS only
- Third-party adapters should be audited before deployment

## Compliance

Snapshot Sleuth is designed to support compliance with:

- SOC 2
- ISO 27001
- NIST Cybersecurity Framework
- GDPR (with proper configuration)

Consult with your compliance team before deploying in regulated environments.
