/**
 * GitHub Issues adapter for ticketing
 */
import { Octokit } from '@octokit/rest';
import { Issue, IssueStatus, Comment, GitHubConfig, formatTimestamp } from '@snapshot-sleuth/shared';
import { ITicketingAdapter } from '../interfaces';

export class GitHubTicketingAdapter implements ITicketingAdapter {
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

  async createTicket(data: {
    title: string;
    description: string;
    labels?: string[];
    assignees?: string[];
  }): Promise<Issue> {
    const { data: issue } = await this.octokit.issues.create({
      owner: this.owner,
      repo: this.repo,
      title: data.title,
      body: data.description,
      labels: data.labels || [],
      assignees: data.assignees || [],
    });

    return this.parseIssue(issue);
  }

  async getTicket(ticketId: string): Promise<Issue | null> {
    try {
      const issueNumber = parseInt(ticketId, 10);
      const { data: issue } = await this.octokit.issues.get({
        owner: this.owner,
        repo: this.repo,
        issue_number: issueNumber,
      });

      return this.parseIssue(issue);
    } catch (error) {
      return null;
    }
  }

  async updateTicketStatus(ticketId: string, status: IssueStatus): Promise<Issue> {
    const issueNumber = parseInt(ticketId, 10);
    const state = status === IssueStatus.CLOSED || status === IssueStatus.RESOLVED ? 'closed' : 'open';

    const { data: issue } = await this.octokit.issues.update({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
      state: state as any,
    });

    return this.parseIssue(issue);
  }

  async addComment(ticketId: string, body: string): Promise<Comment> {
    const issueNumber = parseInt(ticketId, 10);
    const { data: comment } = await this.octokit.issues.createComment({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
      body,
    });

    return {
      id: comment.id.toString(),
      issueId: ticketId,
      body: comment.body || '',
      author: comment.user?.login || 'unknown',
      createdAt: comment.created_at,
      updatedAt: comment.updated_at,
    };
  }

  async listComments(ticketId: string): Promise<Comment[]> {
    const issueNumber = parseInt(ticketId, 10);
    const { data: comments } = await this.octokit.issues.listComments({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
    });

    return comments.map((comment) => ({
      id: comment.id.toString(),
      issueId: ticketId,
      body: comment.body || '',
      author: comment.user?.login || 'unknown',
      createdAt: comment.created_at,
      updatedAt: comment.updated_at,
    }));
  }

  async addLabels(ticketId: string, labels: string[]): Promise<Issue> {
    const issueNumber = parseInt(ticketId, 10);
    const { data: issue } = await this.octokit.issues.addLabels({
      owner: this.owner,
      repo: this.repo,
      issue_number: issueNumber,
      labels,
    });

    return this.parseIssue(issue);
  }

  async closeTicket(ticketId: string): Promise<Issue> {
    return this.updateTicketStatus(ticketId, IssueStatus.CLOSED);
  }

  private parseIssue(issue: any): Issue {
    const status = issue.state === 'closed' ? IssueStatus.CLOSED : IssueStatus.OPEN;

    return {
      id: issue.number.toString(),
      title: issue.title,
      description: issue.body || '',
      status,
      labels: issue.labels.map((l: any) => l.name),
      assignees: issue.assignees?.map((a: any) => a.login) || [],
      createdAt: issue.created_at,
      updatedAt: issue.updated_at,
      url: issue.html_url,
      metadata: {
        githubId: issue.id,
        author: issue.user?.login,
      },
    };
  }
}
