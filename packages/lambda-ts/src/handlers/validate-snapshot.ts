/**
 * Snapshot validation handler
 */
import { Handler } from 'aws-lambda';
import { EC2Client, DescribeSnapshotsCommand } from '@aws-sdk/client-ec2';
import { createLogger } from '@snapshot-sleuth/shared';

const logger = createLogger();
const ec2 = new EC2Client({});

export interface ValidateSnapshotEvent {
  snapshotId: string;
  region: string;
}

export interface ValidateSnapshotResult {
  snapshotId: string;
  region: string;
  validated: boolean;
  snapshot: {
    volumeId: string;
    volumeSize: number;
    encrypted: boolean;
    kmsKeyId?: string;
    description?: string;
    startTime: string;
  };
}

export const handler: Handler<ValidateSnapshotEvent, ValidateSnapshotResult> = async (
  event
) => {
  logger.info('Validating snapshot', { snapshotId: event.snapshotId });

  try {
    const command = new DescribeSnapshotsCommand({
      SnapshotIds: [event.snapshotId],
    });

    const response = await ec2.send(command);

    if (!response.Snapshots || response.Snapshots.length === 0) {
      throw new Error(`Snapshot ${event.snapshotId} not found`);
    }

    const snapshot = response.Snapshots[0];

    logger.info('Snapshot validated successfully', {
      snapshotId: event.snapshotId,
      volumeId: snapshot.VolumeId,
    });

    return {
      snapshotId: event.snapshotId,
      region: event.region,
      validated: true,
      snapshot: {
        volumeId: snapshot.VolumeId!,
        volumeSize: snapshot.VolumeSize!,
        encrypted: snapshot.Encrypted || false,
        kmsKeyId: snapshot.KmsKeyId,
        description: snapshot.Description,
        startTime: snapshot.StartTime?.toISOString() || new Date().toISOString(),
      },
    };
  } catch (error) {
    logger.error('Failed to validate snapshot', {
      snapshotId: event.snapshotId,
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
};
