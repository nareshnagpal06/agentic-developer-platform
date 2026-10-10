/**
 * Unit tests for governed tools MCP configuration.
 *
 * The assertions that matter are the negative ones: default-off, no credential
 * in the config object, and a malformed tool name dropped rather than
 * interpolated into an allowedTools entry.
 */
import {
  GOVERNED_TOOLS_ENABLED,
  GOVERNED_TOOLS_SERVER_NAME,
  GOVERNED_TOOLS_PROMPT,
  getGovernedToolsMcpConfig,
  governedToolNames,
  governedToolsActive,
} from './governed-tools-config';

describe('governed-tools-config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('GOVERNED_TOOLS_ENABLED', () => {
    it('defaults to false when the env var is not set', () => {
      // Module-level const, evaluated at import with the test env (unset → '0').
      // Default-off is what makes merging this change no-op for running agents.
      expect(GOVERNED_TOOLS_ENABLED).toBe(false);
    });
  });

  describe('governedToolsActive', () => {
    it('is false when the flag is off even on a protected run', () => {
      process.env.ADP_AGENT_AUTHORITY_ENABLED = 'true';
      expect(governedToolsActive()).toBe(false);
    });

    it('is false on a legacy run even when the flag is on', () => {
      // A legacy run's identity comes from dispatch environment metadata, which
      // is not an isolation boundary against code executing in the worker. Rather
      // than mount a governed surface whose tenant cannot be trusted, mount none.
      delete process.env.ADP_AGENT_AUTHORITY_ENABLED;
      expect(governedToolsActive()).toBe(false);
    });
  });

  describe('governedToolNames', () => {
    it('returns nothing when no catalogue is configured', () => {
      delete process.env.GOVERNED_TOOLS_LIST;
      expect(governedToolNames()).toEqual([]);
    });

    it('prefixes each configured name for allowedTools', () => {
      process.env.GOVERNED_TOOLS_LIST = 'jira_search___search,finance___report';
      expect(governedToolNames()).toEqual([
        'mcp__governance__jira_search___search',
        'mcp__governance__finance___report',
      ]);
    });

    it('tolerates whitespace and empty entries', () => {
      process.env.GOVERNED_TOOLS_LIST = ' alpha , , beta ';
      expect(governedToolNames()).toEqual([
        'mcp__governance__alpha',
        'mcp__governance__beta',
      ]);
    });

    it.each([
      ['a wildcard', '*'],
      ['a path traversal', '../admin'],
      ['a space-separated pair', 'alpha beta'],
      ['an MCP separator', 'mcp__other__tool'],
      ['a newline injection', 'alpha\nbeta'],
      ['an over-long name', 'a'.repeat(129)],
    ])('drops %s rather than granting it', (_label, value) => {
      process.env.GOVERNED_TOOLS_LIST = value;
      // An allowedTools entry IS a permission. A malformed one either grants
      // nothing silently or reads as a wildcard to a future matcher.
      expect(governedToolNames()).toEqual([]);
    });

    it('keeps valid names alongside invalid ones', () => {
      process.env.GOVERNED_TOOLS_LIST = 'good_tool,*,also-good';
      expect(governedToolNames()).toEqual([
        'mcp__governance__good_tool',
        'mcp__governance__also-good',
      ]);
    });
  });

  describe('getGovernedToolsMcpConfig', () => {
    it('points at the loopback bridge, not the gateway', () => {
      const config = getGovernedToolsMcpConfig();
      expect(config.type).toBe('http');
      expect(config.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/__run\/governed-tools\/mcp\/$/);
    });

    it('carries no credential of any kind', () => {
      // The point of mediation: the worker holds no gateway token. This config is
      // also built once per run and never re-evaluated, so a short-lived token
      // placed here would expire mid-run with no refresh path.
      process.env.ADP_TENANT_ID = 'tenant-one';
      process.env.ADP_OWNER_SUB = 'sub-one';
      const config = getGovernedToolsMcpConfig();
      expect(config.headers).toEqual({});
      expect(JSON.stringify(config)).not.toContain('tenant-one');
      expect(JSON.stringify(config)).not.toContain('sub-one');
    });

    it('honours a configured proxy port', () => {
      process.env.SIGV4_PROXY_PORT = '19090';
      expect(getGovernedToolsMcpConfig().url).toContain('127.0.0.1:19090');
    });

    it('refuses a proxy port that would move the destination off loopback', () => {
      // "9090@evil.example.com" parses as userinfo + host in the bridge URL.
      process.env.SIGV4_PROXY_PORT = '9090@evil.example.com';
      expect(() => getGovernedToolsMcpConfig()).toThrow(/TCP port number/);
    });
  });

  describe('GOVERNED_TOOLS_SERVER_NAME', () => {
    it('is governance', () => {
      expect(GOVERNED_TOOLS_SERVER_NAME).toBe('governance');
    });
  });

  describe('GOVERNED_TOOLS_PROMPT', () => {
    it('tells the agent a refusal is an answer and arguments are scanned', () => {
      expect(GOVERNED_TOOLS_PROMPT).toContain('governance');
      expect(GOVERNED_TOOLS_PROMPT).toMatch(/entitled/i);
      expect(GOVERNED_TOOLS_PROMPT).toMatch(/scanned/i);
      expect(GOVERNED_TOOLS_PROMPT).toMatch(/do not retry/i);
    });
  });
});
