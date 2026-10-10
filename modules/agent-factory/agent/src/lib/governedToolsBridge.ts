/** A loopback transport holding only this worker's run identity, never a gateway token. */
import { IncomingMessage, ServerResponse } from 'node:http';
import { SignatureV4 } from '@smithy/signature-v4';
import { Hash } from '@smithy/hash-node';
import { gatewaySigningRegion, workerAwsCredentials, workerIdentityHeaders } from './runIdentity';
import { proxyPort } from './proxyPort';

/**
 * A sibling of knowledgeBridge rather than a fourth entry in its path table.
 *
 * Same reasoning the gateway gives for splitting its routers: this bridge carries
 * a request that results in a bearer token being minted for an *external*
 * governance gateway, which is a different risk profile from the Door bridge, and
 * it should be reviewable on its own terms. The shared pieces (runIdentity,
 * proxyPort) are already factored out, so the duplication is the error handling
 * and the caps — both of which are load-bearing and better read in place.
 */
export function governedToolsBridgeUrl(): string {
  return `http://127.0.0.1:${proxyPort()}/__run/governed-tools`;
}

const MAX_BODY = 1024 * 1024;
const MAX_RESPONSE = 4 * 1024 * 1024;

/**
 * Governed tool calls require the gateway to resolve identity per request, which
 * is only possible for a protected run. Legacy runs carry dispatch-environment
 * metadata that is not an isolation boundary against code executing inside the
 * worker, so there is deliberately no legacy path here: no protected run, no
 * governed tools.
 */
export function isGovernedToolsRun(): boolean {
  return process.env.ADP_AGENT_AUTHORITY_ENABLED?.toLowerCase() === 'true';
}

/** Called before the model proxy's general path. No redirects or arbitrary paths. */
export async function handleGovernedToolsBridge(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (!req.url?.startsWith('/__run/governed-tools')) return false;
  // Exact-match lookup with a 404 default. This table is what stops the agent
  // choosing a destination; a prefix or regex match here is an SSRF. tools/list
  // and tools/call are both JSON-RPC methods on this one path.
  const paths: Record<string, string> = {
    'POST /__run/governed-tools/mcp/': '/mcp/',
  };
  const path = paths[`${req.method} ${req.url}`];
  if (!isGovernedToolsRun() || !path) {
    res.writeHead(404); res.end('Not found'); return true;
  }
  try {
    const base = process.env.ADP_GATEWAY_ENDPOINT || '';
    const endpoint = new URL(base);
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
      throw new Error('Invalid gateway');
    }
    endpoint.pathname = endpoint.pathname.replace(/\/+$/, '') + '/internal/v1/agent/self/governed-tools' + path;
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += Buffer.byteLength(chunk);
      if (size > MAX_BODY) {
        res.writeHead(413); res.end('Request too large'); return true;
      }
      chunks.push(Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks);
    const signer = new SignatureV4({
      credentials: workerAwsCredentials(), region: gatewaySigningRegion(base),
      service: 'execute-api', sha256: Hash.bind(null, 'sha256'),
    });
    // Reread after upload. Never forward client ACL/auth: the gateway resolves
    // tenant and user from its own tables, so anything sent here would be either
    // ignored or a second channel for a value the caller must not choose.
    const headers = {
      host: endpoint.host, 'content-type': 'application/json',
      accept: 'application/json, text/event-stream', ...workerIdentityHeaders(),
    };
    const signed = await signer.sign({
      method: req.method!, hostname: endpoint.hostname, path: endpoint.pathname,
      protocol: endpoint.protocol, headers, body: body.length ? body : undefined,
    });
    // endpoint is the operator-configured ADP_GATEWAY_ENDPOINT, checked above for https
    // and for inline credentials/query/fragment. The caller cannot contribute to the
    // destination: `path` comes from the fixed lookup table above, so an arbitrary request
    // URL is a 404 before reaching here. redirect:'error' keeps the SigV4 credentials and
    // worker identity headers from following a relocation (#5603).
    // nosemgrep: tmp.gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
    const upstream = await fetch(endpoint, {
      method: req.method, headers: signed.headers, body: body.length ? body : undefined,
      redirect: 'error', signal: AbortSignal.timeout(35_000),
    });
    if (!upstream.ok) {
      await upstream.body?.cancel();
      res.writeHead(upstream.status); res.end('Governed tool request refused'); return true;
    }
    const responseChunks: Uint8Array[] = [];
    let responseSize = 0;
    const reader = upstream.body?.getReader();
    if (reader) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          responseSize += value.length;
          if (responseSize > MAX_RESPONSE) throw new Error('Response too large');
          responseChunks.push(value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
    }
    res.writeHead(upstream.status, {
      'content-type': upstream.headers.get('content-type') || 'application/json',
      'cache-control': 'no-store',
    });
    res.end(Buffer.concat(responseChunks));
  } catch {
    // Provider and HTTP errors can contain credentials or upstream headers.
    res.writeHead(502); res.end('Governed tools service unavailable');
  }
  return true;
}
