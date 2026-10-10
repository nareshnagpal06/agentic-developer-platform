/**
 * Unit tests for the governed-tools loopback bridge.
 *
 * The load-bearing assertion is the path table: it is what stops the agent
 * choosing a destination, so every URL outside it must 404 before any fetch.
 */
import { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { governedToolsBridgeUrl, handleGovernedToolsBridge, isGovernedToolsRun } from './governedToolsBridge';

function request(method: string, url: string, body = ''): IncomingMessage {
  const stream = Readable.from(body ? [Buffer.from(body)] : []) as IncomingMessage;
  stream.method = method;
  stream.url = url;
  stream.headers = {};
  return stream;
}

function response() {
  const res = {
    statusCode: 0,
    body: '',
    writeHead(status: number) { res.statusCode = status; return res; },
    end(chunk?: unknown) { if (chunk) res.body = String(chunk); return res; },
  };
  return res as unknown as ServerResponse & { statusCode: number; body: string };
}

describe('governedToolsBridge', () => {
  const originalEnv = process.env;
  const fetchSpy = jest.fn();

  beforeEach(() => {
    process.env = { ...originalEnv };
    fetchSpy.mockReset();
    global.fetch = fetchSpy as unknown as typeof fetch;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('governedToolsBridgeUrl', () => {
    it('is on loopback', () => {
      expect(governedToolsBridgeUrl()).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/__run\/governed-tools$/);
    });
  });

  describe('isGovernedToolsRun', () => {
    it('is false unless the run is protected', () => {
      delete process.env.ADP_AGENT_AUTHORITY_ENABLED;
      expect(isGovernedToolsRun()).toBe(false);
      process.env.ADP_AGENT_AUTHORITY_ENABLED = 'true';
      expect(isGovernedToolsRun()).toBe(true);
    });
  });

  describe('request routing', () => {
    it('declines URLs outside its own prefix so other handlers can claim them', async () => {
      // Returning false rather than 404 is what lets the Knowledge bridge and
      // the general proxy path still see their own requests.
      const res = response();
      expect(await handleGovernedToolsBridge(request('POST', '/__run/knowledge/call'), res)).toBe(false);
      expect(await handleGovernedToolsBridge(request('GET', '/__health'), res)).toBe(false);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it.each([
      ['an unprotected run', 'POST', '/__run/governed-tools/mcp/'],
      ['a path outside the table', 'POST', '/__run/governed-tools/call'],
      ['a query string', 'POST', '/__run/governed-tools/mcp/?tenant=victim'],
      ['a traversal', 'POST', '/__run/governed-tools/../secrets'],
      ['a wrong method', 'GET', '/__run/governed-tools/mcp/'],
      ['a bare prefix', 'POST', '/__run/governed-tools'],
    ])('404s %s without reaching the network', async (label, method, url) => {
      if (label !== 'an unprotected run') process.env.ADP_AGENT_AUTHORITY_ENABLED = 'true';
      process.env.ADP_GATEWAY_ENDPOINT = 'https://gateway.example.com';
      const res = response();
      expect(await handleGovernedToolsBridge(request(method, url), res)).toBe(true);
      expect(res.statusCode).toBe(404);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('502s rather than leaking error detail when the endpoint is unusable', async () => {
      process.env.ADP_AGENT_AUTHORITY_ENABLED = 'true';
      // http, not https: an operator misconfiguration must not downgrade the
      // transport carrying a request that mints a bearer token.
      process.env.ADP_GATEWAY_ENDPOINT = 'http://gateway.example.com';
      const res = response();
      expect(await handleGovernedToolsBridge(request('POST', '/__run/governed-tools/mcp/'), res)).toBe(true);
      expect(res.statusCode).toBe(502);
      expect(res.body).toBe('Governed tools service unavailable');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('413s an oversized body without reaching the network', async () => {
      process.env.ADP_AGENT_AUTHORITY_ENABLED = 'true';
      process.env.ADP_GATEWAY_ENDPOINT = 'https://gateway.example.com';
      const res = response();
      const oversized = 'x'.repeat(1024 * 1024 + 1);
      await handleGovernedToolsBridge(request('POST', '/__run/governed-tools/mcp/', oversized), res);
      expect(res.statusCode).toBe(413);
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });
});
