# Governance Tab — Frontend + Backend Build Scope

Status: SCOPE / not yet built. This document defines exactly what to build to add a
**Governance** tab to ADP's existing Gateway admin UI: a tool **registry**, a
**review queue** (approve/reject), and an **audit trail** of policy decisions.

It deliberately mirrors patterns already in the gateway so this is additive, not a
new app. Nothing here changes how enforcement works — Cedar in the governance
gateway remains the actual gate. This UI is the human review/visibility layer.

---

## 1. What this tab is (and is NOT)

| Concern | This tab | Where it really lives |
|---|---|---|
| **See what governed tools exist** (catalogue) | ✅ shows it | governance.yaml → deployed targets |
| **Approve / reject a tool** (human sign-off) | ✅ the action | a record in the gateway DB |
| **See who called what + ALLOW/DENY** (audit) | ✅ shows it | AgentCore decision log (CloudWatch) |
| **Actually block/allow a tool call** (enforcement) | ❌ NOT here | Cedar policy in the governance gateway |

Honest boundary (carry from design doc): approving a tool is a **sign-off record**,
not the enforcement switch — UNLESS we turn on `require_approval_to_enable`, which
makes Cedar policy generation conditional on `APPROVED`. That coupling is a
governance-module change, out of scope for the UI itself but noted below.

---

## 2. Three sub-views (tabs within the Governance page)

1. **Registry** — table of all governed tools: name, tenant (org_id), owner,
   status (PENDING / APPROVED / REJECTED), description, created/updated. Filter by
   tenant + status. Click a row → detail drawer.
2. **Review queue** — the subset with status = PENDING. Each row has **Approve** /
   **Reject** buttons (reviewer-gated). Reject asks for a reason.
3. **Audit trail** — read-only list of policy decisions: timestamp, principal
   (org_id / user), tool, decision (ALLOW/DENY), determining policy, latency.
   Filter by tenant + decision + time range.

---

## 3. Backend (FastAPI) — `modules/gateway/src/governance/`

Mirror the `src/knowledge/` and `src/admin/` modules. New package:

```
src/governance/
├── __init__.py
├── routes.py      # APIRouter(prefix="/api/governance", tags=["governance"])
├── schemas.py     # Pydantic request/response models
├── service.py     # DB access + business logic
└── models.py      # SQLAlchemy models (Base + TenantMixin)
```

### 3.1 Wiring (two one-line changes)
- `src/app.py` → add `"src.governance.routes"` to `UNIT_MODULES` (auto-discovered +
  mounted by the existing loop).
- `src/app.py` lifespan (the `if settings.db_auto_create:` model-import block) → add
  `import src.governance.models  # noqa: F401` so local dev create_all sees the tables.
- Admin-gate the whole router the same way the indexing router is gated:
  `router = APIRouter(prefix="/api/governance", tags=["governance"], dependencies=[Depends(require_admin)])`.
  (Reviewer-specific gating: see §3.5.)

### 3.2 Endpoints (mirror knowledge/routes.py list+detail+action shape)

| Method | Path | Purpose | Gate |
|---|---|---|---|
| GET | `/api/governance/tools` | list registry (filters: `tenant`, `status`, `page`, `page_size`) | admin/reviewer |
| GET | `/api/governance/tools/{id}` | tool detail | admin/reviewer |
| POST | `/api/governance/tools` | register a tool → status PENDING | admin |
| POST | `/api/governance/tools/{id}/approve` | set APPROVED, write audit row | reviewer |
| POST | `/api/governance/tools/{id}/reject` | set REJECTED (+ reason), write audit row | reviewer |
| GET | `/api/governance/decisions` | audit trail (filters: `tenant`, `decision`, `since`, `until`, paging) | admin/reviewer |

The `approve`/`reject` verbs copy the shape of knowledge/routes.py `POST /{id}/reindex`
(an action endpoint returning the updated resource).

### 3.3 Response models (schemas.py — copy knowledge/schemas.py shapes)
- `GovernanceToolResponse` { id, name, tenant, owner, handler, description, status,
  created_at, updated_at, reviewed_by, reviewed_at, reject_reason }
- `GovernanceToolListResponse` { items, total, page, page_size, has_more }
- `ToolRegisterRequest` { name, tenant, owner, handler, description }
- `RejectRequest` { reason }
- `DecisionResponse` { id, ts, principal_org_id, principal_sub, tool, decision,
  determining_policy, latency_ms }
- `DecisionListResponse` { items, total, page, page_size, has_more }

### 3.4 Data model (models.py — Base + TenantMixin, mirror admin/models.py)

```python
class GovernanceTool(Base, TenantMixin):        # org_id from TenantMixin = the tenant the tool is fenced to
    __tablename__ = "governance_tools"
    id: Mapped[str]      = mapped_column(String(255), primary_key=True, default=new_uuid)
    name: Mapped[str]    = mapped_column(String(255), index=True)
    owner: Mapped[str]   = mapped_column(String(255), default="")
    handler: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str]  = mapped_column(String(32), default="PENDING", index=True)  # PENDING|APPROVED|REJECTED
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_gov_tool_tenant_name"),)
```

Audit trail: **do NOT store decisions in Postgres from the app**. The authoritative
decisions already exist in the AgentCore decision log
(`/aws/vendedlogs/bedrock-agentcore/adp-governance/APPLICATION_LOGS`). The
`/decisions` endpoint should query CloudWatch Logs Insights on demand (service.py
calls `boto3 logs.start_query`/`get_query_results`) and map rows to `DecisionResponse`.
This avoids a sync pipeline and keeps one source of truth. (The approve/reject
sign-off audit — a different thing — can reuse the existing `admin.models.AuditLog`.)

### 3.5 Reviewer role
Two options:
- **Simple (start here):** gate approve/reject on `require_admin` (platform admin).
  Zero new RBAC. Ship this first.
- **Proper (follow-up):** add `Permission.TOOL_APPROVE` to
  `src/admin/config.py ROLE_PERMISSIONS`, check via `AccessControl.check_permission`,
  and grant it to a `platform-reviewers` group. This is the established extension
  point (per access_control.py).

### 3.6 Where the tool list comes from
The registry table is seeded/synced from `governance.yaml` (the deploy input). Two
choices:
- **Read-through (simplest):** on first load, if the table is empty, import the
  tools from the governance config. Manual re-sync endpoint if needed.
- **Push (later):** the governance `deploy.sh` writes tool records to this API after
  each deploy. Out of scope for v1.

### 3.7 Migration
`alembic/versions/025_governance_tables.py`, `down_revision =
"024_budget_usage_bigint_tokens"` (current head — verify at build time),
`op.create_table("governance_tools", ...)`. No decisions table needed (CloudWatch).

---

## 4. Frontend (React) — `modules/gateway/frontend/`

Stack in place: Vite + React 19 + TS + Tailwind v4 + @tanstack/react-query +
react-router-dom v7. In-house UI kit at `@/components/ui` (Alert, Button, Input,
Select), plus TableSkeleton. Copy `src/pages/AgentActivity.tsx` — it is the
canonical react-query list page (filters + cursor paging + TableSkeleton + Alert
error + status badges + detail modal).

### 4.1 Files to add
```
src/pages/Governance.tsx          # page shell with 3 sub-tabs (Registry|Review|Audit)
src/services/governance.ts        # apiClient calls (copy src/services/activity.ts)
src/types/governance.ts           # GovernanceTool, Decision, list responses
```

### 4.2 Route + nav (two edits)
- `src/App.tsx`:
  `const Governance = lazy(() => import('./pages/Governance'));`
  `<Route path="/governance" element={<AdminGuard><Governance/></AdminGuard>} />`
  (optionally wrap in `<FeatureGate feature="governance">`).
- `src/components/Navigation.tsx`: push a nav item guarded by `isPlatformAdmin()`
  (same pattern as the existing Access Requests item), e.g.
  `{ to: '/governance', label: 'Governance', icon: '🛡️' }`.

### 4.3 Data fetching
`src/services/governance.ts` imports `{ apiClient, buildQueryString }` from
`@/services/api` and exposes: `listTools(params)`, `getTool(id)`, `approveTool(id)`,
`rejectTool(id, reason)`, `listDecisions(params)`. Pages consume them via `useQuery`
/ `useMutation`; invalidate the tools query key after approve/reject.

### 4.4 Gating in-page
Approve/Reject buttons render only when the reviewer permission is present
(`usePermissions()` → `isPlatformAdmin()` for v1, or a new `canApproveTools()` when
§3.5 proper role lands).

---

## 5. Build order (smallest shippable increments)

1. **Registry read-only** — models + migration + `GET /tools` + `GET /tools/{id}` +
   Governance page Registry tab (list + detail). Seed from governance.yaml.
2. **Review actions** — `POST approve` / `POST reject` + admin gating + Review tab
   with buttons. (Sign-off recorded in AuditLog.)
3. **Audit trail** — `GET /decisions` via CloudWatch Logs Insights + Audit tab.
4. **Follow-ups** — reviewer role (`TOOL_APPROVE`), `require_approval_to_enable`
   coupling in the governance module (so Approve actually generates the Cedar
   policy), deploy-time push sync.

Rough size (matches the design doc's Phase 3 estimate): ~650 lines across
SQL + Python + React for steps 1–3.

---

## 6. Anchor references (verified in code)
- Router auto-discovery + admin-guard mount: `modules/gateway/src/app.py`
  (`UNIT_MODULES` list; the `for module_path in UNIT_MODULES` loop; the
  `include_router(indexing_router, dependencies=[Depends(require_admin)])` example).
- CRUD template: `modules/gateway/src/knowledge/routes.py` +
  `modules/gateway/src/knowledge/schemas.py`.
- Auth primitives: `modules/gateway/src/auth/dependencies.py`
  (`get_current_user` → TokenContext with `org_id`/`is_admin`; `require_admin`).
- ORM + audit shapes: `modules/gateway/src/shared/models/base.py` (Base, TenantMixin,
  new_uuid, utcnow); `modules/gateway/src/admin/models.py` (AuditLog).
- RBAC extension point: `modules/gateway/src/admin/access_control.py` +
  `src/admin/config.py` (Permission / ROLE_PERMISSIONS).
- Migrations: `modules/gateway/alembic/versions/` (linear chain; head
  `024_budget_usage_bigint_tokens`).
- Frontend list page to copy: `modules/gateway/frontend/src/pages/AgentActivity.tsx`;
  service `src/services/activity.ts`; API client `src/services/api.ts`; route file
  `src/App.tsx`; nav `src/components/Navigation.tsx`; admin gate
  `src/components/AdminGuard.tsx`.
- Decision log source: CloudWatch group
  `/aws/vendedlogs/bedrock-agentcore/adp-governance/APPLICATION_LOGS`.
