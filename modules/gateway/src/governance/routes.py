"""Governance tool-registry API router.

Backs the "Governance" tab in the gateway admin UI. Step 1 is read-only:
    GET /api/governance/tools        list + filter + paginate the registry
    GET /api/governance/tools/{id}   tool detail
Approve/reject actions and the audit trail are added in later steps.

Auth: the whole router is admin-only (require_admin), matching how the
agent-context indexing admin router is mounted in app.py.

Gating: the module-level ``router`` symbol is only defined when
GOVERNANCE_UI_ENABLED=true. app.py's UNIT_MODULES loop checks
``hasattr(module, "router")`` — so when the flag is off, these routes are
silently skipped (same technique as src/knowledge/routes.py + AGENT_CONTEXT_ENABLED).
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.admin.access_control import AccessControl
from src.admin.config import Permission
from src.admin.exceptions import AccessDeniedError, InvalidScopeError
from src.auth.dependencies import get_current_user, require_admin
from src.governance import decisions as decisions_reader
from src.governance import service
from src.governance.models import VALID_STATUSES
from src.governance.schemas import (
    DecisionListResponse,
    DecisionResponse,
    GovernanceConfigResponse,
    GovernanceToolDetailResponse,
    GovernanceToolListResponse,
    GovernanceToolResponse,
    RejectRequest,
    SyncRequest,
    SyncResponse,
)
from src.shared.database import get_db

logger = logging.getLogger("bedrockgateway.governance.routes")

# All routes require a platform admin (step 1). A dedicated reviewer role is a
# later enhancement (Permission.TOOL_APPROVE via AccessControl).
_router = APIRouter(
    prefix="/governance",
    tags=["governance"],
    dependencies=[Depends(require_admin)],
)


@_router.get("/config", response_model=GovernanceConfigResponse)
async def get_config(
    current_user: Annotated[Any, Depends(get_current_user)],
) -> GovernanceConfigResponse:
    """Return UI-facing governance flags so the tab describes itself honestly."""
    approval_enables = (
        os.environ.get("GOVERNANCE_APPROVAL_ENABLES_TOOL", "").lower() == "true"
    )
    # decisions.py always falls back to a default log group, so the audit tab
    # always has a source; this flag is here for future explicit-disable support.
    return GovernanceConfigResponse(
        approval_enables_tool=approval_enables,
        decision_log_configured=True,
    )


@_router.get("/tools", response_model=GovernanceToolListResponse)
async def list_tools(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Any, Depends(get_current_user)],
    tenant: Annotated[str | None, Query(description="Filter by tenant (org_id)")] = None,
    status: Annotated[str | None, Query(description="Filter by review status")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
) -> GovernanceToolListResponse:
    """List governed tools in the registry (admin: across all tenants)."""
    if status is not None and status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {VALID_STATUSES}",
        )

    items, total = await service.list_tools(
        db,
        tenant=tenant,
        status=status,
        page=page,
        page_size=page_size,
    )
    return GovernanceToolListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total,
    )


@_router.post("/tools/sync", response_model=SyncResponse)
async def sync_registry(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Any, Depends(get_current_user)],
    body: SyncRequest | None = None,
) -> SyncResponse:
    """Upsert the registry from the governance config.

    Two seed sources (body wins):
      * body.tools — the deploy-time push path (a deploy step forwards the
        governance.yaml tool list). Primary path; works in a deployed gateway.
      * else GOVERNANCE_CONFIG_PATH file — local/in-repo convenience.

    Idempotent and review-safe: existing tools keep their review status; only
    new tools are added as PENDING (see service.sync_tools).
    """
    tools = body.tools if body and body.tools else service.load_tools_from_config_file()
    if not tools:
        raise HTTPException(
            status_code=400,
            detail=(
                "No tools to sync: provide a 'tools' body or set GOVERNANCE_CONFIG_PATH "
                "to a governance.yaml on the gateway."
            ),
        )
    created, updated, total = await service.sync_tools(db, tools)
    logger.info(
        "governance registry sync by %s: created=%d updated=%d total=%d",
        getattr(current_user, "user_id", "?"),
        created,
        updated,
        total,
    )
    return SyncResponse(created=created, updated=updated, total=total)


@_router.get("/tools/{tool_id}", response_model=GovernanceToolDetailResponse)
async def get_tool_detail(
    tool_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Any, Depends(get_current_user)],
) -> GovernanceToolDetailResponse:
    """Get detail for one governed tool."""
    tool = await service.get_tool(db, tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Governed tool not found")
    return GovernanceToolDetailResponse(**tool.model_dump())


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP for the audit row."""
    return request.client.host if request.client else None


async def _require_tool_review(
    db: AsyncSession, current_user: Any, tool_id: str
) -> Any:
    """Fetch the tool and authorize the caller to review it.

    Returns the tool (as a response object) or raises 404 if missing.

    Authorization: the router already requires a platform admin (require_admin),
    so this is defensive-in-depth and the plumbing for a future non-platform
    reviewer role. It checks Permission.TOOL_APPROVE scoped to the tool's tenant,
    so an org-admin reviewer (once the router guard is relaxed) could only review
    tools fenced to their own org. Platform admins pass unconditionally.
    """
    tool = await service.get_tool(db, tool_id)
    if not tool:
        raise HTTPException(status_code=404, detail="Governed tool not found")
    try:
        await AccessControl(db).check_permission(
            current_user,
            Permission.TOOL_APPROVE,
            target_org_id=tool.tenant,
        )
    except (AccessDeniedError, InvalidScopeError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return tool


@_router.post("/tools/{tool_id}/approve", response_model=GovernanceToolResponse)
async def approve_tool(
    tool_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Any, Depends(get_current_user)],
) -> GovernanceToolResponse:
    """Approve a governed tool (human sign-off).

    Honest boundary: approval is a review RECORD. It only turns a tool on if the
    governance module's require_approval_to_enable is set — otherwise Cedar
    already fences by tenant and this is review-only.
    """
    await _require_tool_review(db, current_user, tool_id)
    updated = await service.review_tool(
        db,
        tool_id=tool_id,
        approve=True,
        reviewer_id=getattr(current_user, "user_id", "unknown"),
        reason=None,
        client_ip=_client_ip(request),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Governed tool not found")
    return updated


@_router.post("/tools/{tool_id}/reject", response_model=GovernanceToolResponse)
async def reject_tool(
    tool_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[Any, Depends(get_current_user)],
    body: RejectRequest | None = None,
) -> GovernanceToolResponse:
    """Reject a governed tool with an optional reason."""
    await _require_tool_review(db, current_user, tool_id)
    updated = await service.review_tool(
        db,
        tool_id=tool_id,
        approve=False,
        reviewer_id=getattr(current_user, "user_id", "unknown"),
        reason=(body.reason if body else "") or "",
        client_ip=_client_ip(request),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Governed tool not found")
    return updated


@_router.get("/decisions", response_model=DecisionListResponse)
async def list_decisions(
    current_user: Annotated[Any, Depends(get_current_user)],
    decision: Annotated[str | None, Query(description="Filter: ALLOW or DENY")] = None,
    tenant: Annotated[str | None, Query(description="Best-effort tenant filter")] = None,
    since_ms: Annotated[int | None, Query(description="Window start, epoch millis")] = None,
    until_ms: Annotated[int | None, Query(description="Window end, epoch millis")] = None,
) -> DecisionListResponse:
    """Audit trail: policy decisions read live from the AgentCore decision log.

    Read-only, no Postgres — the CloudWatch log is the single source of truth.
    Degrades to an empty list if the log group is unset/absent (never 500s).
    """
    if decision is not None and decision.upper() not in ("ALLOW", "DENY"):
        raise HTTPException(status_code=400, detail="decision must be ALLOW or DENY")

    raw, truncated = decisions_reader.get_decisions(
        since_ms=since_ms,
        until_ms=until_ms,
        decision_filter=decision,
        tenant=tenant,
    )
    items = [DecisionResponse(**r) for r in raw]
    return DecisionListResponse(items=items, count=len(items), truncated=truncated)


# ---------------------------------------------------------------------------
# Conditional export — gated behind GOVERNANCE_UI_ENABLED (default off)
# ---------------------------------------------------------------------------

if os.environ.get("GOVERNANCE_UI_ENABLED", "").lower() == "true":
    router = _router
