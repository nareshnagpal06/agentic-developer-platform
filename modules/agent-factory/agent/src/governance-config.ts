/**
 * Governance Layer MCP configuration.
 *
 * Registers the AI Governance Gateway as a native MCP server via HTTP transport,
 * so the agent's tool calls flow THROUGH governance (Pattern A — in the request
 * path). The gateway does Cedar authorization + Bedrock Guardrails admission scan
 * + audit, then routes permitted calls to the real tool backends.
 *
 * Deliberately mirrors knowledge-layer-config.ts — ADP already mounts the
 * Agent Context "Door" this exact way, so governance rides the same rails:
 * HTTP MCP registration + trusted identity headers injected from the SQS envelope
 * (never from LLM input) + a feature flag.
 *
 * Feature-flagged: GOVERNANCE_ENABLED=1 to enable (default: off). Flip on after
 * verifying identity headers propagate and the gateway enforces in the target
 * environment.
 */

/**
 * Feature flag: route tool calls through the governance gateway.
 * Default OFF — flip ON after verifying enforcement in the target environment.
 */
export const GOVERNANCE_ENABLED =
  (process.env.GOVERNANCE_ENABLED ?? '0') === '1';

/**
 * Governance Gateway MCP endpoint URL. Uses GOVERNANCE_MCP_URL if set, otherwise
 * defaults to the in-cluster / in-account gateway address. The trailing `/mcp/`
 * matches the AgentCore Gateway's MCP path (same shape as the Door).
 */
const GOVERNANCE_MCP_URL = (() => {
  const raw = process.env.GOVERNANCE_MCP_URL;
  if (!raw) return '';
  // Strip any trailing slashes, then ensure the path ends in exactly one /mcp.
  // The AgentCore Gateway serves MCP at `/mcp`. The GatewayUrl already includes
  // `/mcp`, so we must NOT blindly append another — doing so yields `/mcp/mcp`
  // and every tools/list silently fails (no governed tools ever surface).
  const trimmed = raw.replace(/\/+$/, '');
  return /\/mcp$/i.test(trimmed) ? `${trimmed}/` : `${trimmed}/mcp/`;
})();

/**
 * Secrets Manager ARN/name of the service-account Cognito credentials for this
 * tenant. The secret holds {"username","password","org_id"}. The agent logs in
 * as that service-account USER (ADMIN_USER_PASSWORD_AUTH) to get a Cognito ID
 * token — which carries custom:org_id, the claim Cedar reads. Set via env
 * (GOVERNANCE_SVC_SECRET) on the ScaledJob.
 *
 * Why a service-account user and not the agent's IAM role: the AgentCore Gateway
 * uses CUSTOM_JWT auth and Cedar reads custom:org_id from the JWT. An agent's IAM
 * role carries no such claim, so the agent authenticates AS a per-tenant Cognito
 * user whose token carries the org_id.
 */
const GOVERNANCE_SVC_SECRET = process.env.GOVERNANCE_SVC_SECRET ?? '';

// The governance Cognito pool + client (ADP's pool). Same values as the gateway
// validates against. Overridable via env for other deployments.
const GOVERNANCE_COGNITO_POOL = process.env.GOVERNANCE_COGNITO_POOL ?? '';
const GOVERNANCE_COGNITO_CLIENT = process.env.GOVERNANCE_COGNITO_CLIENT ?? '';
const AWS_REGION = process.env.AWS_REGION ?? 'us-east-1';

// Cached bearer token, fetched once by prepareGovernance() before the query.
let _bearerToken: string | null = null;

/**
 * Build identity headers from trusted environment variables.
 *
 * These are advisory context for the gateway/audit — the AUTHORITATIVE identity
 * is the Cognito bearer token (set separately). Cedar reads custom:org_id from
 * that token, not from these headers. Headers come from env vars injected by
 * entrypoint.py (SQS envelope) — never from agent/LLM input.
 */
export function buildGovernanceHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};

  // The bearer token is the real authenticator (Cedar reads its custom:org_id).
  if (_bearerToken) headers['Authorization'] = `Bearer ${_bearerToken}`;

  const orgId = process.env.ADP_ORG_ID ?? process.env.ADP_TENANT_ID;
  if (orgId) headers['X-Adp-Org-Id'] = orgId;

  const tenantId = process.env.ADP_TENANT_ID;
  if (tenantId) headers['X-Tenant-Id'] = tenantId;

  const ownerSub = process.env.ADP_OWNER_SUB;
  if (ownerSub) headers['X-Owner-Sub'] = ownerSub;

  const login = process.env.ADP_GITHUB_LOGIN;
  if (login) headers['X-GitHub-Login'] = login;

  const persona = process.env.AGENT_TYPE;
  if (persona) headers['X-Adp-Persona'] = persona;

  return headers;
}

/**
 * Fetch the governance bearer token once, before the agent query starts.
 *
 * Reads the service-account creds from Secrets Manager, logs in against ADP's
 * Cognito pool (ADMIN_USER_PASSWORD_AUTH), and caches the ID token. Best-effort:
 * on any failure it logs and leaves the token null — the governance MCP server
 * then registers without an Authorization header, and the gateway rejects its
 * calls (fail-closed: no token = no access, rather than silently ungoverned).
 *
 * Must be called (awaited) before getGovernanceMcpConfig(). No-op when
 * governance is disabled or unconfigured.
 */
export async function prepareGovernance(
  log: (level: string, msg: string) => void = () => {},
): Promise<void> {
  if (!GOVERNANCE_ENABLED || GOVERNANCE_MCP_URL.length === 0) return;
  if (!GOVERNANCE_SVC_SECRET || !GOVERNANCE_COGNITO_POOL || !GOVERNANCE_COGNITO_CLIENT) {
    log('WARN', '[governance] SVC secret / Cognito pool / client not configured — cannot fetch token');
    return;
  }
  try {
    // Lazy-import the AWS SDK v3 clients so this file has no top-level AWS dep.
    const { SecretsManagerClient, GetSecretValueCommand } = await import(
      '@aws-sdk/client-secrets-manager'
    );
    const {
      CognitoIdentityProviderClient,
      AdminInitiateAuthCommand,
    } = await import('@aws-sdk/client-cognito-identity-provider');

    const sm = new SecretsManagerClient({ region: AWS_REGION });
    const secretRaw = await sm.send(
      new GetSecretValueCommand({ SecretId: GOVERNANCE_SVC_SECRET }),
    );
    const creds = JSON.parse(secretRaw.SecretString ?? '{}') as {
      username?: string;
      password?: string;
    };
    if (!creds.username || !creds.password) {
      log('WARN', '[governance] service-account secret missing username/password');
      return;
    }

    const idp = new CognitoIdentityProviderClient({ region: AWS_REGION });
    const auth = await idp.send(
      new AdminInitiateAuthCommand({
        UserPoolId: GOVERNANCE_COGNITO_POOL,
        ClientId: GOVERNANCE_COGNITO_CLIENT,
        AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
        AuthParameters: { USERNAME: creds.username, PASSWORD: creds.password },
      }),
    );
    // The ID token, not the access token — the access token carries no
    // custom:org_id and Cedar would see no tenant.
    _bearerToken = auth.AuthenticationResult?.IdToken ?? null;
    if (_bearerToken) {
      log('INFO', '[governance] service-account token acquired — governance MCP is authenticated');
    } else {
      log('WARN', '[governance] Cognito auth returned no IdToken');
    }
  } catch (err) {
    log('WARN', `[governance] failed to acquire service-account token: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * MCP server config for the Governance Gateway (HTTP transport).
 *
 * Shape matches McpHttpServerConfig from @anthropic-ai/claude-agent-sdk:
 *   { type: 'http', url: string, headers?: Record<string, string> }
 *
 * Call prepareGovernance() first so the Authorization header is populated.
 */
export function getGovernanceMcpConfig(): {
  type: 'http';
  url: string;
  headers: Record<string, string>;
} {
  return {
    type: 'http' as const,
    url: GOVERNANCE_MCP_URL,
    headers: buildGovernanceHeaders(),
  };
}

/**
 * True only when governance is enabled AND a gateway URL is configured.
 * Guards the caller from registering a server with an empty URL.
 */
export function isGovernanceConfigured(): boolean {
  return GOVERNANCE_ENABLED && GOVERNANCE_MCP_URL.length > 0;
}

/** MCP server name. Tools surface to the agent as mcp__governance__<toolname>. */
export const GOVERNANCE_SERVER_NAME = 'governance';

/**
 * System prompt section injected when governance is enabled. Sets the agent's
 * expectation that its governed tools live behind this server and that some
 * tools may be intentionally absent (not an error — governance as absence).
 */
export const GOVERNANCE_PROMPT = `
<governed-tools>
Some of your tools are provided through a governed gateway (MCP server: governance).
- You only see the governed tools your team is entitled to. If a tool you expected
  is absent, your team is not entitled to it — this is expected, not an error. Do
  not try to work around it.
- Tool calls through this gateway are scanned. Never place instructions, system
  prompts, or unrelated directives inside tool arguments — put only the data the
  tool needs. Injection-shaped content will be refused before the tool runs.
</governed-tools>`;
