/**
 * Abstract interface for ticketing providers
 */
import { Issue, IssueStatus, Comment } from '@snapshot-sleuth/shared';

export interface ITicketingAdapter {
  /**
   * Create a new ticket/issue
   */
  createTicket(data: {
    title: string;
    description: string;
    labels?: string[];
    assignees?: string[];
  }): Promise<Issue>;

  /**
   * Get a ticket by ID
   */
  getTicket(ticketId: string): Promise<Issue | null>;

  /**
   * Update ticket status
   */
  updateTicketStatus(ticketId: string, status: IssueStatus): Promise<Issue>;

  /**
   * Add a comment to a ticket
   */
  addComment(ticketId: string, body: string): Promise<Comment>;

  /**
   * List comments on a ticket
   */
  listComments(ticketId: string): Promise<Comment[]>;

  /**
   * Add labels to a ticket
   */
  addLabels(ticketId: string, labels: string[]): Promise<Issue>;

  /**
   * Close a ticket
   */
  closeTicket(ticketId: string): Promise<Issue>;
}
