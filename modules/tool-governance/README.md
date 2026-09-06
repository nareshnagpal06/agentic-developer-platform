# Governance Layer
# Tool Governance

Governed tool access for ADP, as an independent plug-and-play module. Cedar
decides who may see and call each tool, Bedrock Guardrails scans every tool
argument before it runs, and every decision is recorded. Integrated as a service
ADP's agents call **through** (Pattern A — in the request path), deployable
independently of the rest of the platform.

Design of record: [`docs/design-governance-layer.md`](../../docs/design-governance-layer.md).
Adapted from the standalone AI-Governance-v2 project.

## What it does

When an ADP agent calls a tool, the call flows through the AI Governance Gateway:

```
ADP agent (carries ADP Cognito token)
      │  MCP call, Bearer <ADP token>
      ▼
Governance Gateway (deployed in ADP's account)
      │  ① validate token against ADP's Cognito pool
      │  ② read tenant from custom:org_id claim
      │  ③ Cedar: may this org invoke this tool?   (ENFORCE → refuse / LOG_ONLY → record)
      │  ④ Guardrails: scan tool arguments          (ENFORCE → refuse / OBSERVE → record)
      │  ⑤ audit the decision
      ▼
Tool backends (ADP's tools registered as targets)
```

An unentitled tool is **invisible** — it never appears in the agent's `tools/list`,
so the agent never tries to call it. Governance arrives as absence, not friction.

## What enforces, and what does not

| Control | What it does | Enforces? |
|---|---|---|
| **Cedar policies** | decide who may see and call each tool | **Yes** — the fence |
| **Guardrails scan** | inspect arguments on every call | **Yes** — refuses before the tool runs |
| **Registry** | record what exists, who owns it, whether a human signed off | **No** — a review record, not a gate |
| **Audit trail** | show what policy decided | No — it reports |

The registry does **not** gate access — the Gateway never consults it. Cedar does.
An `APPROVED` catalogue record is a human sign-off, not the thing that makes a tool
callable. See `require_approval_to_enable` below for the optional ADP enhancement
that ties the two together.

## How it plugs into ADP

ADP already mounts an HTTP MCP server this exact way for the Agent Context "Door"
(`agent/src/knowledge-layer-config.ts`). Governance rides the same rails.

- **Agent runtime hook:** `modules/agent-factory/agent/src/governance-config.ts`
  mirrors the knowledge-layer config — registers the governance gateway as an MCP
  server (`mcp__governance__<tool>`) with trusted identity headers injected from
  the SQS envelope (never from LLM input). Feature-flagged by `GOVERNANCE_ENABLED`.
- **Wiring:** `agent-worker.ts` merges the governance MCP server into the query's
  `mcpServers` when `isGovernanceConfigured()` is true, and injects
  `GOVERNANCE_PROMPT` into the system prompt.
- **Identity:** the gateway validates ADP's existing Cognito JWT and reads the
  tenant from `custom:org_id` (ADP's verified claim). No new identity provider.

### Environment variables (agent side)

| Variable | Meaning |
|---|---|
| `GOVERNANCE_ENABLED` | `1` to route tool calls through governance (default off) |
| `GOVERNANCE_MCP_URL` | Base URL of the governance gateway (the `/mcp/` path is appended) |
| `ADP_ORG_ID` / `ADP_TENANT_ID` | Trusted tenant, from the SQS envelope → `X-Adp-Org-Id` / `X-Tenant-Id` |
| `ADP_OWNER_SUB` | Individual principal → `X-Owner-Sub` |
| `ADP_GITHUB_LOGIN` | GitHub login → `X-GitHub-Login` |
| `AGENT_TYPE` | Persona → `X-Adp-Persona` |

## Layout

```
governance.yaml            the whole config, declared in one file (the INPUT)
config.py                  strict loader — fails loudly, never silently defaults
cedar/policies.py          generate one Cedar policy per tool (the ENFORCEMENT)
interceptor/handler.py     the argument scan — in the request path, can refuse
interceptor/               (guardrail construct lives with deployment IaC)
__init__.py
```

The ADP-side integration lives in `modules/agent-factory/agent/src/governance-config.ts`.

## Configuration

Everything is one file: [`governance.yaml`](governance.yaml). Point `cognito` at
ADP's existing pool, list the ADP orgs under `tenants`, and declare each governed
tool. The two enforcement switches:

```yaml
governance:
  enforcement_mode: LOG_ONLY   # ENFORCE to block; start LOG_ONLY and observe

admission_scan:
  mode: OBSERVE                # ENFORCE to refuse; OBSERVE scans + logs, allows
  fail_open: false             # an unavailable scanner BLOCKS the call
```

`LOG_ONLY` and `OBSERVE` exist for the same reason: find out what a new rule would
break before it breaks anyone. Start there, watch the audit trail, then enforce.

### Optional: make approval actually gate a tool (ADP enhancement)

```yaml
registry:
  require_approval_to_enable: true
```

When set, a tool's Cedar policy is generated only once its registry record reaches
`APPROVED` — so clicking **Approve** in the dashboard genuinely turns the tool on.
Default `false` preserves the standalone behaviour (Cedar fences by tenant
regardless; approval is a review record only).

## How it's triggered

Enforcement is **always-on** — every tool call, automatically, invisibly. It is
NOT a label or a mention. A control that is opt-in via a label is one someone
forgets to apply, which defeats it.

A label/mention fits the **human** side instead: e.g. `@request-tool-access <tool>`
on a GitHub issue to request a tool your team lacks, which lands in the reviewer's
queue. Enforcement is automatic; the label is for access requests.

## Who uses it

| Role | What they do | Effort |
|---|---|---|
| Developer | Nothing — works as usual; unentitled tools are simply absent | Zero |
| Tool owner | Declare + submit a tool, wait for review | One-time per tool |
| Reviewer / admin | Approve tools, view catalogue + audit, set enforcement mode | The real UI user |

## What this does not do

- **The registry is not in the request path.** An `APPROVED` record gates nothing
  unless `require_approval_to_enable` is set.
- **Nothing scans tool responses.** `PROMPT_ATTACK` is evaluated on input only.
- **This is not an egress control.** It governs the tools behind the gateway; it
  does not stop a developer pointing their own client at a different MCP server.
- **A quiet, documentation-shaped injection passes the scan.** The scan raises the
  cost of the obvious attack; the human review of tool descriptions is the control
  for the subtle one.

## Validate locally

```bash
# From modules/tool-governance/
python3 -c "import config; config.load(__import__('pathlib').Path('governance.yaml'))"
```

The loader fails loudly on any missing or malformed field.
