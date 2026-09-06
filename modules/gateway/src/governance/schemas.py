"""Pydantic request/response models for the governance tool-registry API.

Shapes mirror src/knowledge/schemas.py (AssetResponse / AssetListResponse) so the
frontend list/detail patterns carry over unchanged.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ToolSpec(BaseModel):
    """One governed tool as declared in governance.yaml (the deploy input).

    This is the seed/sync payload shape — the caller (deploy step or admin)
    pushes the current set of governed tools; the gateway upserts them into the
    registry catalogue. Kept intentionally close to the governance.yaml tool
    block so a deploy script can forward it with minimal transformation.
    """

    name: str = Field(..., max_length=255)
    tenant: str = Field(..., max_length=255, description="org_id the tool is fenced to")
    owner: str = Field("", max_length=255)
    handler: str = Field("", max_length=512)
    description: str = ""


class SyncRequest(BaseModel):
    """POST /api/governance/tools/sync — upsert the registry from a tool list."""

    tools: list[ToolSpec]


class SyncResponse(BaseModel):
    """Result of a registry sync."""

    created: int
    updated: int
    total: int


class RejectRequest(BaseModel):
    """POST /api/governance/tools/{id}/reject — reason for the rejection."""

    reason: str = Field("", max_length=2048)


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class GovernanceToolResponse(BaseModel):
    """Single governed tool in list/detail responses."""

    id: str
    name: str
    tenant: str = Field(..., description="org_id the tool is fenced to")
    owner: str = ""
    handler: str = ""
    description: str = ""
    status: str
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    reject_reason: str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class GovernanceToolListResponse(BaseModel):
    """GET /api/governance/tools — paginated list."""

    items: list[GovernanceToolResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


class GovernanceToolDetailResponse(GovernanceToolResponse):
    """GET /api/governance/tools/{id} — full detail (extends the list item)."""

    pass


# ---------------------------------------------------------------------------
# Audit trail (policy decisions from the AgentCore decision log)
# ---------------------------------------------------------------------------


class DecisionResponse(BaseModel):
    """One policy-evaluation decision read from the AgentCore decision log."""

    ts: datetime
    decision: str = Field(..., description="ALLOW or DENY")
    principal: str | None = Field(None, description="Cedar principal entity id (OAuthUser sub)")
    tool: str | None = Field(None, description="Tool name if resolvable from the request")
    determining_policies: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    request_id: str | None = None


class DecisionListResponse(BaseModel):
    """GET /api/governance/decisions — a page of decisions (log-driven, cursor-less)."""

    items: list[DecisionResponse]
    count: int
    # The decision log is queried live; there is no offset paging. `truncated`
    # signals the scan hit its cap and older entries may exist beyond the window.
    truncated: bool = False


# ---------------------------------------------------------------------------
# Config (what the UI needs to describe itself honestly)
# ---------------------------------------------------------------------------


class GovernanceConfigResponse(BaseModel):
    """GET /api/governance/config — flags the UI needs to tell the truth.

    ``approval_enables_tool`` mirrors the governance module's
    require_approval_to_enable. When true, approving a tool in the registry is
    what generates its Cedar policy (so Approve genuinely turns the tool on).
    When false (default), Cedar fences by tenant regardless and approval is a
    review record only. The UI uses this to word the Approve action correctly.
    """

    approval_enables_tool: bool = False
    decision_log_configured: bool = True
