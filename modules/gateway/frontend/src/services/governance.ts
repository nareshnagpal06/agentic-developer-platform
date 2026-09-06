/**
 * API client for the Governance tool-registry.
 *
 * Mirrors the pattern in services/activity.ts — thin functions over apiClient +
 * buildQueryString. Step 1 is read-only (list + detail); approve/reject land in
 * a later step.
 */

import { apiClient, buildQueryString } from './api';
import type {
  GovernanceConfig,
  GovernanceDecisionListResponse,
  GovernanceDecisionQueryParams,
  GovernanceTool,
  GovernanceToolListResponse,
  GovernanceToolQueryParams,
} from '@/types/governance';

/** Fetch UI-facing governance flags (how to word the Approve action, etc.). */
export async function getGovernanceConfig(): Promise<GovernanceConfig> {
  return apiClient.get<GovernanceConfig>('/governance/config');
}

/**
 * List governed tools in the registry. Admin-scoped on the server (across all
 * tenants unless `tenant` is passed).
 */
export async function listGovernanceTools(
  params?: GovernanceToolQueryParams,
): Promise<GovernanceToolListResponse> {
  const query = buildQueryString({
    tenant: params?.tenant,
    status: params?.status,
    page: params?.page || 1,
    page_size: params?.page_size || 20,
  });

  const response = await apiClient.get<GovernanceToolListResponse>(
    `/governance/tools${query}`,
  );

  return {
    items: Array.isArray(response?.items) ? response.items : [],
    total: response?.total ?? 0,
    page: response?.page ?? 1,
    page_size: response?.page_size ?? 20,
    has_more: response?.has_more ?? false,
  };
}

/** Fetch detail for one governed tool. */
export async function getGovernanceTool(toolId: string): Promise<GovernanceTool> {
  return apiClient.get<GovernanceTool>(
    `/governance/tools/${encodeURIComponent(toolId)}`,
  );
}

/** Approve a governed tool (reviewer sign-off). */
export async function approveGovernanceTool(
  toolId: string,
): Promise<GovernanceTool> {
  return apiClient.post<GovernanceTool>(
    `/governance/tools/${encodeURIComponent(toolId)}/approve`,
  );
}

/** Reject a governed tool with an optional reason. */
export async function rejectGovernanceTool(
  toolId: string,
  reason: string,
): Promise<GovernanceTool> {
  return apiClient.post<GovernanceTool>(
    `/governance/tools/${encodeURIComponent(toolId)}/reject`,
    { reason },
  );
}

/**
 * List policy decisions (audit trail), read live from the AgentCore decision log.
 * Read-only; degrades to an empty list if the log group is not configured.
 */
export async function listGovernanceDecisions(
  params?: GovernanceDecisionQueryParams,
): Promise<GovernanceDecisionListResponse> {
  const query = buildQueryString({
    decision: params?.decision,
    tenant: params?.tenant,
    since_ms: params?.since_ms,
    until_ms: params?.until_ms,
  });

  const response = await apiClient.get<GovernanceDecisionListResponse>(
    `/governance/decisions${query}`,
  );

  return {
    items: Array.isArray(response?.items) ? response.items : [],
    count: response?.count ?? 0,
    truncated: response?.truncated ?? false,
  };
}
