# Design: AI Governance Integration with ADP (Pattern A — Governance as a Service)

**Author:** Naresh Nagpal
**Status:** Proposal (revised)
**Date:** 2026-08-23

---

## 1. Summary

ADP provides everything for running agents (identity, scaling, model access, tool
routing) **except** governance of tool access. The AI-Governance solution provides
exactly that missing layer.

Rather than rebuilding governance inside ADP, we integrate the **existing**
AI-Governance solution **as-is**: ADP routes agent tool traffic *through* the
governance gateway (Pattern A — in the request path), and ADP's frontend gets one
additional tab for the tool registry / approval workflow.

This is a loose-coupling, service-composition approach:
- AI-Governance stays a standalone, independently-deployable service
- ADP calls it over a clean boundary (MCP / single endpoint)
- Almost no code changes — mostly configuration

---

## 2. What Each Side Provides

| Concern | Provided by |
|---|---|
| Agent runtime, scaling, triggers | ADP (Agent Factory) |
| Model access (Bedrock proxy) | ADP (Gateway) |
| Code intelligence / memory | ADP (Agent Context) |
| Identity (Cognito, tenants, roles) | ADP (existing) |
| Tool routing (MCP Hub) | ADP (planned) |
| **Tool access policy (who can call what)** | **AI-Governance (Cedar)** |
| **Argument scanning (injection defense)** | **AI-Governance (Bedrock Guardrails)** |
| **Tool registry + review workflow** | **AI-Governance (AgentCore Registry)** |
| **Decision audit trail** | **AI-Governance (CloudWatch)** |

---

## 3. Integration Architecture (Pattern A — In the Request Path)

```
ADP agent (carries ADP Cognito token)
      │
      │ MCP call, Authorization: Bearer <ADP token>
      ▼
┌─── AI-Governance Gateway (deployed in ADP's AWS account, as-is) ───┐
│                                                                   │
│  ① Validate token against ADP's Cognito pool                     │
│  ② Read tenant from custom:org_id claim                          │
│  ③ Cedar: may this principal invoke this tool?                   │
│     · ENFORCE → refuse / unentitled tools invisible in list      │
│     · LOG_ONLY → record decision, allow                          │
│  ④ Guardrails: scan tool arguments (PROMPT_ATTACK)               │
│     · ENFORCE → refuse before tool runs                          │
│     · OBSERVE → record, allow                                    │
│  ⑤ Audit: write the decision                                     │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
      │
      ▼
Tool backends (ADP's domain tools, registered as Gateway targets)
```

**Why Pattern A (in-path):** The core principle of the AI-Governance project is
that *a control only enforces if it is in the request path.* Advisory/decision-API
patterns (Pattern B) would move enforcement into ADP and weaken the guarantee.
Pattern A keeps enforcement inside the governance gateway, exactly as it works
today.

---

## 4. Identity Flow — Use ADP's Cognito Claims

The governance gateway already does `CUSTOM_JWT` auth against a Cognito pool. We
simply point it at **ADP's** pool instead of the standalone one. No token
translation, no trust bridge, one identity provider.

**Config change (governance.yaml):**
```yaml
cognito:
  user_pool_id: <ADP's pool id>       # was the standalone pool
  app_client_id: <ADP's client id>
  tenant_claim: "custom:org_id"        # ADP's tenant lives here (verified)
```

**ADP's verified Cognito custom claims:**
| Claim | Meaning |
|---|---|
| `custom:org_id` | Org / tenant → maps to Cedar tenant |
| `custom:team_id` | Team |
| `custom:department_id` | Department |
| `custom:role` | Role (e.g. platform_admin) |
| `custom:tenant_id` | Used in the agent-factory path |

ADP's agents already receive these claims (injected by ADP's Pre-Token-Generation
Lambda). The token an ADP agent already carries is validated by the governance
gateway against the same pool that issued it. **No change on ADP's side for
identity.**

Cedar policies use `custom:org_id` as the principal's tenant:
```cedar
permit(
  principal in ADP::Org::"finance",
  action == Action::"invoke",
  resource == ADP::Tool::"finance-reports"
);
```

---

## 5. Tool Registration — Manual First (Option 1)

**Clarifying the `governance.yaml` vs AWS AgentCore Registry relationship:**

These are NOT competing — they are a pipeline. `governance.yaml` is the **input**;
the AWS AgentCore Registry records are one of the **outputs**.

```
governance.yaml (authored by platform admin)
        │
        │ cdk deploy reads it
        ▼
┌───────────────────────────────────────────┐
│  Creates AWS resources:                   │
│   · Cedar policies      (ENFORCEMENT)     │
│   · Gateway targets     (routing)         │
│   · AgentCore Registry records (CATALOGUE)│ ◄── the review queue
│   · Bedrock Guardrail   (SCANNING)        │
└───────────────────────────────────────────┘
```

| Artifact | What it is | Role |
|---|---|---|
| `governance.yaml` | The declaration file you edit + deploy from | Input / source of truth |
| Cedar policies | Generated from governance.yaml | **Enforces** — in request path |
| AWS AgentCore Registry | The catalogue (records land here after deploy) | **Review workflow only** — NOT a gate |
| Bedrock Guardrail | The argument scanner | **Enforces** — in request path |

**For the integration (Option 1 — manual):**
- ADP's tools are declared in `governance.yaml`, one block per tool
- On `cdk deploy`, each tool → a Gateway target + Cedar policy + Registry record
- The Registry records land with status PENDING (auto_approval: false)
- The ADP frontend tab reads these records for the review queue

**Later (Option 2 — automated):** ADP pushes tool declarations to the registry API
when a domain app deploys a tool, auto-creating target + policy. Deferred until the
manual pattern is validated.

---

## 6. Frontend — One Additional Tab in ADP's Dashboard

ADP already has a React admin UI (orgs, teams, budgets, usage). We add **one tab**:

- **Registry / Review Queue tab**
  - Lists all tools with owner, tenant, status (PENDING / APPROVED / REJECTED)
  - Reviewer can Approve / Reject (requires the reviewer role/group)
  - Optionally: catalogue view + audit trail sub-views

**Implementation:** the ADP frontend calls the AI-Governance registry read/write
API and renders natively (no separate app, no iframe needed). Reviewer permission
reuses ADP's existing role model (`custom:role` / a reviewer group).

---

## 7. The Honest Nuance — Approval Is Review, Not a Gate (Today)

The AWS AgentCore Registry does **not** gate tool access. The Gateway never
consults it. So clicking "Approve" in the ADP tab is a **human sign-off record**,
not the thing that makes a tool callable — **Cedar** does that.

This must be stated plainly so nobody assumes the approve button is the enforcement
point (this is the exact overclaim the project's engineering notes warn about).

**Optional enhancement for ADP:** make Cedar policy generation *conditional on
Registry status = APPROVED*. Then "Approve" genuinely turns the tool on — a
deliberate improvement over the standalone behavior. Worth discussing with the
owner as a decision, not assuming it.

---

## 8. Deployment — Runs in ADP's Account

The governance stack deploys **into ADP's AWS account** (confirmed). This
simplifies everything:

- No cross-account IAM / STS
- Gateway validates ADP's Cognito tokens directly (same account)
- Bedrock Guardrail runs in the same region/account as ADP's Bedrock
- Audit logs land in the same CloudWatch

**Deploy steps:**
1. Set `governance.yaml` → ADP's Cognito pool + ADP's tools
2. `cdk deploy` the governance stack into ADP's account
3. ADP points its agents' MCP client at the governance gateway URL
4. Add the registry tab to ADP's frontend

---

## 9. What Changes From the Standalone Project

| Thing | Standalone | Integrated (Pattern A) |
|---|---|---|
| Where it runs | Own account | ADP's account |
| Cognito pool | Own pool | ADP's pool |
| Tenant claim | `custom:tenant` | `custom:org_id` |
| Tools | 2 demo tools | ADP's real tools (governance.yaml, Option 1) |
| Frontend | Standalone dashboard | Tab in ADP's dashboard (calls registry API) |
| Code changes | — | Mostly configuration; logic/engine unchanged |
| Enforcement | In-path (Cedar + scan) | Unchanged — still in-path |

The key win: **almost no code changes** — it's mostly configuration. The CDK stack,
Cedar engine, Guardrail, and registry deploy as-is into ADP's account, pointed at
ADP's Cognito.

---

## 10. Open Decisions

| Decision | Options | Recommendation |
|---|---|---|
| Approval gates access? | Review-only (today) vs Cedar-conditional-on-APPROVED | Discuss with owner; Cedar-conditional is a clean enhancement for ADP |
| Tool registration | Manual governance.yaml (now) vs API-pushed (later) | Manual first, automate after validation |
| Frontend integration | Native (call registry API) vs embed dashboard | Native — cleaner, reuses ADP's UI shell |
| Enforcement rollout | Start ENFORCE vs start LOG_ONLY/OBSERVE | Start LOG_ONLY/OBSERVE, flip to ENFORCE after observing real traffic |

---

## 11. How It's Triggered — Enforcement Is Always-On, Not Label-Driven

There was a suggestion to trigger governance with a GitHub label / `@tools` mention.
This section explains why enforcement must be always-on, and where a label/mention
genuinely does fit.

### Two different moments in ADP (the source of confusion)

| Moment | What happens | Who acts | How often |
|---|---|---|---|
| **1. Trigger an agent** | Label an issue `developer` → an agent spins up | Human, once | Once per issue |
| **2. Agent calls a tool** | Running agent invokes search/terraform/db/etc. | The agent, autonomously | Many times per run |

**Governance belongs at Moment 2 — every tool call — not Moment 1.**

### Why a label can't be the enforcement switch

A label is a Moment-1 action: a human applies it once at the start. But governance
is a check on *every* tool call the agent makes during its run — the human isn't
present for each call. You cannot express "scan every argument on every call" as a
label a human applies once.

More importantly: **a security control that is opt-in via a label is one someone
forgets to apply.** An agent without the label would run ungoverned — which defeats
the entire purpose. The original project exists precisely because "the control point
cannot be a config file someone may or may not use." A label is the same trap.

**Therefore: enforcement (Cedar + argument scan) is always-on for every agent's tool
calls. No label. Invisible to the developer.** Governance is a property of the
platform, like auth or logging.

### Where a label / mention DOES fit — the human actions

Governance has human-in-the-loop moments that map perfectly to GitHub-native
triggers. These are *requests and approvals*, not enforcement:

| Trigger | Action | Fits a label/mention? |
|---|---|---|
| `@request-tool-access <tool>` on an issue | Developer requests access to a tool their team lacks → enters review queue | **Yes** — genuine human action |
| Reviewer approves/rejects in dashboard | Human sign-off on a pending tool | Dashboard button (or a mention) |
| Enforcement rollout (LOG_ONLY→ENFORCE) | Admin flips mode | Config, not a label |

So the honest split:
- **Enforcement** = automatic, every call, invisible. NOT a label.
- **Access requests / approvals** = human actions. A label/mention (`@request-tool-access`)
  or dashboard button fits here.

### How to frame this to the owner

> "Enforcement of tool policy has to be always-on and in the request path — if it's
> opt-in via a label, an agent without the label runs ungoverned, which defeats the
> control. So governance runs invisibly on every agent's tool call.
>
> But a label/mention DOES fit the **human** parts: `@request-tool-access` to request
> a tool, and the reviewer approving tools in the dashboard. Those are real human
> actions. So enforcement is automatic; the label is for access requests."

---

## 12. Questions to Confirm With the Owner

1. **MCP endpoint wiring** — how do ADP agents get pointed at the governance
   gateway? A configured MCP endpoint in the agent runtime, or via the MCP Hub?
   (Note: ADP already mounts an HTTP MCP server this way for the Knowledge Layer /
   Agent Context "Door" — the governance gateway rides the same rails.)
2. **Which tools first** — which ADP tools should be governed initially (a domain
   app's tools, or platform-wide)?
3. **Should approval gate access** (the Section 7 enhancement)?
4. **Reviewer role** — reuse an existing ADP role or add a `platform-reviewers`
   group?
5. **Access-request UX** — is `@request-tool-access` on a GitHub issue the right
   trigger for the human request path, or a dashboard-only flow?
