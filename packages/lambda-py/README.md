# Python Lambda Functions

This package contains Python Lambda functions for executing forensic tools.

## Structure

```
handlers/
├── yara_scanner.py        # YARA rule-based scanning
├── clamav_scanner.py      # ClamAV malware scanning
├── wolverine_scanner.py   # Wolverine artifact extraction
└── log2timeline.py        # Timeline generation
```

## Requirements

- Python 3.11+
- boto3 (AWS SDK)
- yara-python
- ClamAV
- Additional forensic tools

## Building

```bash
pnpm build
```

This will:
1. Install Python dependencies to `dist/`
2. Package handler code
3. Create deployment artifacts

## Deployment

Lambda functions are deployed via CDK stack in `packages/cdk`.

## Testing

```bash
python -m pytest tests/
```

## Note

Some forensic tools require custom Lambda layers or container images due to size constraints.
