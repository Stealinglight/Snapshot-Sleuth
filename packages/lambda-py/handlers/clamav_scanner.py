"""
ClamAV malware scanning handler
"""
import json
import os
import boto3
import subprocess
from typing import Dict, List, Any

s3 = boto3.client('s3')


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Execute ClamAV malware scan against a mounted snapshot volume
    
    Args:
        event: Lambda event containing snapshotId and volumeId
        context: Lambda context
        
    Returns:
        Dictionary with scan results and findings
    """
    snapshot_id = event.get('snapshotId')
    volume_id = event.get('volumeId')
    
    print(f'Starting ClamAV scan for snapshot {snapshot_id}')
    
    try:
        # Update virus definitions
        print('Updating ClamAV virus definitions...')
        subprocess.run(['freshclam'], check=True)
        
        # Scan mounted filesystem
        mount_point = '/mnt/evidence'
        
        # Run ClamAV scan
        result = subprocess.run(
            ['clamscan', '-r', '-i', '--log=/tmp/clamscan.log', mount_point],
            capture_output=True,
            text=True
        )
        
        # Parse scan results
        findings = []
        with open('/tmp/clamscan.log', 'r') as log_file:
            for line in log_file:
                if 'FOUND' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        findings.append({
                            'file': parts[0].strip(),
                            'signature': parts[1].strip(),
                            'severity': 'HIGH',
                        })
        
        print(f'ClamAV scan complete. Found {len(findings)} threats.')
        
        return {
            'toolName': 'CLAMAV',
            'snapshotId': snapshot_id,
            'status': 'COMPLETED',
            'findings': findings,
            'findingsCount': len(findings),
        }
        
    except Exception as e:
        print(f'Error during ClamAV scan: {str(e)}')
        return {
            'toolName': 'CLAMAV',
            'snapshotId': snapshot_id,
            'status': 'FAILED',
            'error': str(e),
        }
