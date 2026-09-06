/**
 * Types for the Governance tool-registry.
 *
 * Mirrors the backend Pydantic shapes in src/governance/schemas.py.
 * The registry is a review/catalogue record — enforcement is Cedar in the
 * governance gateway, not this table.
 */

export type GovernanceToolStatus = 'PENDING' | 'APPROVED' | 'REJECTED';

export interface GovernanceTool {
  id: string;
  name: string;
  tenant: string; // org_id the tool is fenced to
  owner: string;
  handler: string;
  description: string;
  status: GovernanceToolStatus;
  reviewed_by: string | null;
  reviewed_at: string | null;
  reject_reason: string | null;
  created_at: string;
  updated_at: string | null;
}

export interface GovernanceToolListResponse {
  items: GovernanceTool[];
  total: number;
  page: number;
  page_size: number;
  has_more: boolean;
}

export interface GovernanceToolQueryParams {
  tenant?: string;
  status?: GovernanceToolStatus;
  page?: number;
  page_size?: number;
}

export type DecisionOutcome = 'ALLOW' | 'DENY';

export interface GovernanceDecision {
  ts: string;
  decision: string; // ALLOW | DENY (server-normalized)
  principal: string | null;
  tool: string | null;
  determining_policies: string[];
  latency_ms: number | null;
  request_id: string | null;
}

export interface GovernanceDecisionListResponse {
  items: GovernanceDecision[];
  count: number;
  truncated: boolean;
}

export interface GovernanceDecisionQueryParams {
  decision?: DecisionOutcome;
  tenant?: string;
  since_ms?: number;
  until_ms?: number;
}

export interface GovernanceConfig {
  approval_enables_tool: boolean;
  decision_log_configured: boolean;
}
