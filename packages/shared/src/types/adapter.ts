/**
 * Adapter types and interfaces for pluggable integrations
 */

/**
 * Provider types for integrations
 */
export enum ProviderType {
  GITHUB = 'GITHUB',
  JIRA = 'JIRA',
  LINEAR = 'LINEAR',
  ZENDESK = 'ZENDESK',
  CUSTOM = 'CUSTOM',
}

/**
 * Issue/ticket status
 */
export enum IssueStatus {
  OPEN = 'OPEN',
  IN_PROGRESS = 'IN_PROGRESS',
  CLOSED = 'CLOSED',
  RESOLVED = 'RESOLVED',
}

/**
 * Issue/ticket
 */
export interface Issue {
  id: string;
  title: string;
  description: string;
  status: IssueStatus;
  labels: string[];
  assignees: string[];
  createdAt: string;
  updatedAt: string;
  url: string;
  metadata: Record<string, unknown>;
}

/**
 * Comment on an issue/ticket
 */
export interface Comment {
  id: string;
  issueId: string;
  body: string;
  author: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * GitHub provider configuration
 */
export interface GitHubConfig {
  token: string;
  owner: string;
  repo: string;
  apiUrl?: string;
}

/**
 * Jira provider configuration
 */
export interface JiraConfig {
  host: string;
  email: string;
  apiToken: string;
  projectKey: string;
}

/**
 * Linear provider configuration
 */
export interface LinearConfig {
  apiKey: string;
  teamId: string;
}

/**
 * Zendesk provider configuration
 */
export interface ZendeskConfig {
  subdomain: string;
  email: string;
  apiToken: string;
}
