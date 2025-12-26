# Troubleshooting Guide

## Common Issues

### Installation Issues

#### pnpm install fails

**Error**: `ENOENT: no such file or directory`

**Solution**:
```bash
# Clear caches
pnpm store prune
rm -rf node_modules
rm pnpm-lock.yaml

# Reinstall
pnpm install
```

#### Build fails with TypeScript errors

**Error**: `Cannot find module '@snapshot-sleuth/shared'`

**Solution**:
```bash
# Build packages in order
cd packages/shared && pnpm build
cd ../adapters && pnpm build
cd ../cdk && pnpm build
```

### Deployment Issues

#### CDK bootstrap fails

**Error**: `Unable to resolve AWS account to use`

**Solution**:
```bash
# Configure AWS credentials
aws configure

# Set explicit account and region
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1

# Bootstrap again
pnpm cdk bootstrap
```

#### Stack deployment fails with permission errors

**Error**: `User is not authorized to perform: iam:CreateRole`

**Solution**: Ensure your AWS user/role has sufficient permissions:
- IAM role creation
- S3 bucket creation
- Lambda function deployment
- Step Functions creation
- CloudWatch logging

#### Resource limits exceeded

**Error**: `LimitExceededException: Cannot exceed quota`

**Solution**:
- Check AWS service quotas in the Service Quotas console
- Request quota increases if needed
- Use a different region with available capacity

### Runtime Issues

#### Lambda function timeout

**Error**: `Task timed out after 900.00 seconds`

**Solution**:
1. Increase Lambda timeout in CDK stack:
```typescript
timeout: cdk.Duration.minutes(15)
```

2. Optimize tool execution:
   - Reduce scan scope
   - Use incremental scanning
   - Parallelize where possible

#### Out of memory errors

**Error**: `Runtime exited with error: signal: killed`

**Solution**:
1. Increase Lambda memory:
```typescript
memorySize: 3008 // MB
```

2. For large snapshots, consider:
   - Using EC2 for analysis instead of Lambda
   - Chunking the analysis
   - Streaming results to S3

#### Snapshot not found

**Error**: `Snapshot snap-xxxxx not found`

**Solution**:
1. Verify snapshot exists:
```bash
aws ec2 describe-snapshots --snapshot-ids snap-xxxxx
```

2. Check cross-account sharing:
   - Verify snapshot is shared with your account
   - Check KMS key permissions if encrypted

### Adapter Issues

#### GitHub adapter fails

**Error**: `Bad credentials`

**Solution**:
1. Verify GitHub token:
```bash
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
```

2. Ensure token has required scopes:
   - `repo` - Full control of private repositories
   - `write:org` - Write org and team membership

#### Slack notifications not received

**Error**: Silent failure

**Solution**:
1. Test webhook:
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test"}' \
  YOUR_WEBHOOK_URL
```

2. Check Slack app permissions:
   - Incoming Webhooks enabled
   - Posted to correct channel

### Monitoring Issues

#### CloudWatch logs not appearing

**Solution**:
1. Check log group exists:
```bash
aws logs describe-log-groups --log-group-name-prefix /aws/snapshot-sleuth
```

2. Verify Lambda execution role has logging permissions:
```json
{
  "Effect": "Allow",
  "Action": [
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ],
  "Resource": "*"
}
```

#### Dashboard not showing metrics

**Solution**:
1. Wait for metrics to populate (5-10 minutes)
2. Verify Step Functions are executing
3. Check CloudWatch service health

### Frontend Issues

#### Frontend build fails

**Error**: `Module not found: Error: Can't resolve 'react'`

**Solution**:
```bash
cd packages/frontend
rm -rf node_modules
pnpm install
pnpm build
```

#### Frontend not connecting to backend

**Solution**:
1. Check API Gateway URL in frontend config
2. Verify CORS settings in API Gateway
3. Check browser console for errors

### Data Issues

#### Evidence not uploading to S3

**Error**: `Access Denied`

**Solution**:
1. Verify bucket policy allows Lambda to write
2. Check KMS key permissions if using encryption
3. Ensure S3 bucket exists in correct region

#### Findings not appearing in GitHub Issues

**Solution**:
1. Check GitHub token permissions
2. Verify repository exists and is accessible
3. Check Lambda logs for API errors

## Getting Help

If you continue to experience issues:

1. **Check the logs**:
   - CloudWatch Logs for Lambda functions
   - CloudTrail for AWS API calls
   - CDK deployment output

2. **Enable debug logging**:
```bash
export DEBUG=true
pnpm cdk deploy
```

3. **Open an issue**:
   - Include error messages
   - Provide relevant logs
   - Describe steps to reproduce

4. **Community support**:
   - GitHub Discussions
   - Project documentation
   - AWS Support (for AWS-specific issues)

## Performance Optimization

### Slow forensic scans

1. **Use parallel execution** - Already configured in Step Functions
2. **Optimize scan scope** - Focus on specific paths
3. **Use incremental scanning** - Only scan changed blocks
4. **Consider EC2** - For very large snapshots

### High costs

1. **Enable lifecycle policies** - Move old evidence to Glacier
2. **Delete old snapshots** - Implement retention policies
3. **Optimize Lambda** - Right-size memory and timeout
4. **Use spot instances** - For non-critical analysis

### Cold start issues

1. **Provision concurrency** - For critical Lambda functions
2. **Use Lambda SnapStart** - For Java functions
3. **Warm up functions** - Scheduled CloudWatch Events

## Best Practices

1. **Test in development first** - Don't deploy directly to production
2. **Use version control** - Tag releases appropriately
3. **Monitor costs** - Set up billing alerts
4. **Regular backups** - Of configuration and state
5. **Security scanning** - Run regularly on dependencies
