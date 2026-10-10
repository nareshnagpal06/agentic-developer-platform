/**
 * Governed tools MCP configuration.
 *
 * Builds the mcpServers entry for mounting the external governance gateway as a
 * native MCP server. Every tool call through it is checked against the caller's
 * tenant and identity before the tool runs.
 *
 * Feature-flagged: GOVERNED_TOOLS_ENABLED=1 to enable (default: off).
 *
 * Transport is the loopback bridge, not the gateway itself: the worker holds no
 * governance-gateway credential. The gateway resolves identity per request from
 * its own authority tables and mints a short-lived token there. See
 * lib/governedToolsBridge.ts.
 */

import { governedToolsBridgeUrl, isGovernedToolsRun } from './lib/governedToolsBridge';

/**
 * Feature flag: register governed tools as MCP tools.
 * Default OFF — flip ON after verifying, in the target environment, that the
 * gateway resolves tenant correctly and that a cross-tenant call is refused.
 * The cross-tenant refusal is the assertion that matters: a policy set that
 * allows everything passes any test that only checks a tenant can reach its own
 * tools.
 */
export const GOVERNED_TOOLS_ENABLED =
  (process.env.GOVERNED_TOOLS_ENABLED ?? '0') === '1';

/** MCP server name. Tools surface as mcp__governance__<name>. */
export const GOVERNED_TOOLS_SERVER_NAME = 'governance';

/**
 * Tool names the governance gateway advertises, prefixed for allowedTools.
 *
 * Operator-configured rather than hardcoded, because the catalogue lives in the
 * governance layer's config and is per-deployment — a list baked in here would
 * be wrong for every deployment but one. Names arrive as a comma-separated list
 * of the gateway's own `<target>___<tool>` action names.
 *
 * Entries are validated rather than interpolated as-is: an `allowedTools` entry
 * is a permission, and a malformed one either silently grants nothing or, worse,
 * reads as a wildcard to a future matcher. Anything that is not a plain tool
 * name is dropped.
 *
 * `mcp__` is rejected as a substring on top of the character class, and the
 * character class alone is not enough to catch it: `_` has to stay legal because
 * the gateway's own action names are `<target>___<tool>` (`jira_search___search`),
 * so a configured `mcp__other__tool` would otherwise pass and be prefixed into
 * `mcp__governance__mcp__other__tool` -- a name that reads as addressing a
 * different MCP server than the one it was granted against.
 */
export function governedToolNames(): string[] {
  const configured = process.env.GOVERNED_TOOLS_LIST ?? '';
  return configured
    .split(',')
    .map(name => name.trim())
    .filter(name => /^[A-Za-z0-9_-]{1,128}$/.test(name) && !name.includes('mcp__'))
    .map(name => `mcp__${GOVERNED_TOOLS_SERVER_NAME}__${name}`);
}

/** Tool names exposed by the governance gateway, prefixed for use in allowedTools. */
export const GOVERNED_TOOLS = governedToolNames();

/**
 * MCP server config for the governance gateway (HTTP transport over loopback).
 *
 * Shape matches McpHttpServerConfig from @anthropic-ai/claude-agent-sdk:
 *   { type: 'http', url: string, headers?: Record<string, string> }
 *
 * No headers, and this is the point rather than an omission: there is no
 * credential for the worker to hold. This config object is built once per run
 * and never re-evaluated, so a short-lived token placed here would expire
 * mid-run with no refresh path. A loopback URL does not expire.
 */
export function getGovernedToolsMcpConfig(): {
  type: 'http';
  url: string;
  headers: Record<string, string>;
} {
  return {
    type: 'http' as const,
    url: `${governedToolsBridgeUrl()}/mcp/`,
    headers: {},
  };
}

/**
 * Whether governed tools should actually be mounted for this run.
 *
 * Both conditions are required. The flag is the operator's intent; the
 * protected-run check is whether identity can be resolved per request at all.
 * A legacy run carries dispatch-environment metadata, which is not an isolation
 * boundary against code executing inside the worker — so rather than mount a
 * governed surface whose tenant cannot be trusted, mount nothing.
 */
export function governedToolsActive(): boolean {
  return GOVERNED_TOOLS_ENABLED && isGovernedToolsRun();
}

/**
 * System prompt section injected when governed tools are enabled.
 *
 * States the two things an agent cannot infer from the tool list: that calls are
 * policy-checked (so a refusal is an answer, not a transient error to retry),
 * and that arguments are scanned (so instructions must not be smuggled into
 * them). The entitlement note matters because the catalogue is already filtered
 * per tenant — an absent tool is not a missing tool.
 */
export const GOVERNED_TOOLS_PROMPT = `
<governed-tools>
Some of your tools are provided through a governed gateway (MCP server: governance).
- You only see the governed tools your team is entitled to. If a tool you expected
  is absent, your team is not entitled to it — this is expected, not an error. Do
  not try to work around it.
- Tool calls through this gateway are scanned. Never place instructions, system
  prompts, or unrelated directives inside tool arguments — put only the data the
  tool needs. Injection-shaped content will be refused before the tool runs.
- A refused call is a policy decision. Report it and move on; do not retry it,
  rephrase it to get past the check, or look for an ungoverned route to the same
  data.
</governed-tools>
`;
