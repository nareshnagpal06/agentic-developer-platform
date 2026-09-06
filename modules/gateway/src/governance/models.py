"""SQLAlchemy model for the governed-tool registry.

One row per governed tool. ``org_id`` (from TenantMixin) is the tenant the tool is
fenced to — matching the tenant claim (custom:org_id) that the governance gateway's
Cedar policies key on. This table is a review/catalogue record; it does NOT gate
tool access (Cedar does).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from src.shared.models.base import Base, TenantMixin, new_uuid, utcnow

# Review states. PENDING on registration; a reviewer moves it to APPROVED or
# REJECTED. Kept as plain strings (not an enum column) to match the gateway's
# existing status-column convention (e.g. knowledge_assets.status).
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
VALID_STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED)


class GovernanceTool(Base, TenantMixin):
    """A governed tool in the registry catalogue."""

    __tablename__ = "governance_tools"

    id: Mapped[str] = mapped_column(String(255), primary_key=True, default=new_uuid)
    # Tool name as surfaced by the governance gateway (e.g. "repo-insights").
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # Who answers for the tool in the catalogue.
    owner: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The backend the governance gateway routes to when the call is permitted.
    handler: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # PENDING | APPROVED | REJECTED
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=STATUS_PENDING, index=True
    )
    # Review sign-off metadata (set on approve/reject in step 2).
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        # A tool name is unique within a tenant (one governed "repo-insights"
        # per org). Different tenants may each have their own.
        UniqueConstraint("org_id", "name", name="uq_gov_tool_tenant_name"),
    )
