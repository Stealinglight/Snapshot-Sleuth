/**
 * Abstract interface for case management providers
 */
import { Case, CaseStatus, CaseSummary } from '@snapshot-sleuth/shared';

export interface ICaseManagementAdapter {
  /**
   * Create a new case
   */
  createCase(caseData: Omit<Case, 'id' | 'createdAt' | 'updatedAt'>): Promise<Case>;

  /**
   * Get a case by ID
   */
  getCase(caseId: string): Promise<Case | null>;

  /**
   * Update case status
   */
  updateCaseStatus(caseId: string, status: CaseStatus): Promise<Case>;

  /**
   * Add metadata to a case
   */
  addCaseMetadata(caseId: string, metadata: Record<string, unknown>): Promise<Case>;

  /**
   * List all cases
   */
  listCases(filters?: { status?: CaseStatus; limit?: number }): Promise<Case[]>;

  /**
   * Get case summary with results
   */
  getCaseSummary(caseId: string): Promise<CaseSummary | null>;

  /**
   * Close a case
   */
  closeCase(caseId: string): Promise<Case>;
}
