/**
 * GitHub Issues adapter for case management
 */
import { Octokit } from '@octokit/rest';
import {
  Case,
  CaseStatus,
  CaseSummary,
  GitHubConfig,
  generateCaseId,
  formatTimestamp,
} from '@snapshot-sleuth/shared';
import { ICaseManagementAdapter } from '../interfaces';

export class GitHubCaseManagementAdapter implements ICaseManagementAdapter {
  private octokit: Octokit;
  private owner: string;
  private repo: string;

  constructor(config: GitHubConfig) {
    this.octokit = new Octokit({
      auth: config.token,
      baseUrl: config.apiUrl,
    });
    this.owner = config.owner;
    this.repo = config.repo;
  }

  async createCase(caseData: Omit<Case, 'id' | 'createdAt' | 'updatedAt'>): Promise<Case> {
    const caseId = generateCaseId();
    const now = formatTimestamp();

    const body = this.formatCaseBody(caseData);
    const labels = ['case', `status:${caseData.status.toLowerCase()}`];

    const { data: issue } = await this.octokit.issues.create({
      owner: this.owner,
      repo: this.repo,
      title: `Case: ${caseId} - Snapshot ${caseData.snapshotId}`,
      body,
      labels,
    });

    const caseObj: Case = {
      id: caseId,
      ...caseData,
      createdAt: now,
      updatedAt: now,
      metadata: {
        ...caseData.metadata,
        githubIssueNumber: issue.number,
        githubIssueUrl: issue.html_url,
      },
    };

    return caseObj;
  }

  async getCase(caseId: string): Promise<Case | null> {
    const issues = await this.searchCaseIssues(caseId);
    if (issues.length === 0) {
      return null;
    }

    return this.parseIssueToCase(issues[0]);
  }

  async updateCaseStatus(caseId: string, status: CaseStatus): Promise<Case> {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) {
      throw new Error(`Case ${caseId} not found`);
    }

    const issueNumber = caseObj.metadata.githubIssueNumber as number;
    const labels = await this.updateIssueLabels(issueNumber, status);

    const state = status === CaseStatus.CLOSED ? 'closed' : 'open';
    await this.octokit.issues.update({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
      state: state as any,
      labels,
    });

    return {
      ...caseObj,
      status,
      updatedAt: formatTimestamp(),
    };
  }

  async addCaseMetadata(caseId: string, metadata: Record<string, unknown>): Promise<Case> {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) {
      throw new Error(`Case ${caseId} not found`);
    }

    const issueNumber = caseObj.metadata.githubIssueNumber as number;
    const body = this.formatCaseBody({
      ...caseObj,
      metadata: { ...caseObj.metadata, ...metadata },
    });

    await this.octokit.issues.update({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
      body,
    });

    return {
      ...caseObj,
      metadata: { ...caseObj.metadata, ...metadata },
      updatedAt: formatTimestamp(),
    };
  }

  async listCases(filters?: { status?: CaseStatus; limit?: number }): Promise<Case[]> {
    const labels = ['case'];
    if (filters?.status) {
      labels.push(`status:${filters.status.toLowerCase()}`);
    }

    const { data: issues } = await this.octokit.issues.listForRepo({
      owner: this.owner,
      repo: this.repo,
      labels: labels.join(','),
      per_page: filters?.limit || 100,
    });

    return issues.map((issue) => this.parseIssueToCase(issue));
  }

  async getCaseSummary(caseId: string): Promise<CaseSummary | null> {
    const caseObj = await this.getCase(caseId);
    if (!caseObj) {
      return null;
    }

    // TODO: Aggregate tool results from comments or linked artifacts
    return {
      ...caseObj,
      totalFindings: 0,
      criticalFindings: 0,
      highFindings: 0,
      toolResults: [],
    };
  }

  async closeCase(caseId: string): Promise<Case> {
    return this.updateCaseStatus(caseId, CaseStatus.CLOSED);
  }

  private formatCaseBody(caseData: Partial<Case>): string {
    return `
## Case Details

- **Snapshot ID**: ${caseData.snapshotId}
- **Region**: ${caseData.region}
- **Account ID**: ${caseData.accountId}
- **Status**: ${caseData.status}
- **Priority**: ${caseData.priority}
- **Created By**: ${caseData.createdBy}

## Tags
${Object.entries(caseData.tags || {})
  .map(([key, value]) => `- **${key}**: ${value}`)
  .join('\n')}

## Metadata
\`\`\`json
${JSON.stringify(caseData.metadata, null, 2)}
\`\`\`
`;
  }

  private async searchCaseIssues(caseId: string): Promise<any[]> {
    const query = `repo:${this.owner}/${this.repo} is:issue ${caseId} in:title label:case`;
    const { data } = await this.octokit.search.issuesAndPullRequests({ q: query });
    return data.items;
  }

  private parseIssueToCase(issue: any): Case {
    const title = issue.title as string;
    const caseIdMatch = title.match(/Case:\s+([A-Z]+-\d+-[A-F0-9]+)/);
    const caseId = caseIdMatch ? caseIdMatch[1] : `UNKNOWN-${issue.number}`;

    const statusLabel = issue.labels.find((l: any) => l.name.startsWith('status:'));
    const status = statusLabel
      ? (statusLabel.name.replace('status:', '').toUpperCase() as CaseStatus)
      : CaseStatus.CREATED;

    return {
      id: caseId,
      snapshotId: 'unknown',
      region: 'unknown',
      accountId: 'unknown',
      status,
      createdAt: issue.created_at,
      updatedAt: issue.updated_at,
      createdBy: issue.user.login,
      priority: 'MEDIUM' as any,
      tags: {},
      metadata: {
        githubIssueNumber: issue.number,
        githubIssueUrl: issue.html_url,
      },
    };
  }

  private async updateIssueLabels(issueNumber: number, status: CaseStatus): Promise<string[]> {
    const { data: issue } = await this.octokit.issues.get({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
    });

    const labels = issue.labels
      .map((l: any) => l.name)
      .filter((name: string) => !name.startsWith('status:'));

    labels.push(`status:${status.toLowerCase()}`);
    return labels;
  }
}
