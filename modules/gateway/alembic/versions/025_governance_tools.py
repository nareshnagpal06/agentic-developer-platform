"""Create governance_tools table (governed-tool registry catalogue).

Backs the Governance tab in the admin UI. One row per governed tool, fenced to a
tenant (org_id), with a review status (PENDING/APPROVED/REJECTED). This is a
review/catalogue record — Cedar in the governance gateway is the actual gate.

Revision ID: 025_governance_tools
Revises: 024_budget_usage_bigint_tokens
Create Date: 2026-08-23
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "025_governance_tools"
down_revision: str = "024_budget_usage_bigint_tokens"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the governance_tools table."""
    op.create_table(
        "governance_tools",
        sa.Column("id", sa.String(length=255), nullable=False),
        sa.Column("org_id", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("handler", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("reviewed_by", sa.String(length=255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reject_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "name", name="uq_gov_tool_tenant_name"),
    )
    op.create_index("ix_governance_tools_org_id", "governance_tools", ["org_id"])
    op.create_index("ix_governance_tools_name", "governance_tools", ["name"])
    op.create_index("ix_governance_tools_status", "governance_tools", ["status"])
    op.create_index("ix_governance_tools_created_at", "governance_tools", ["created_at"])


def downgrade() -> None:
    """Drop the governance_tools table."""
    op.drop_index("ix_governance_tools_created_at", table_name="governance_tools")
    op.drop_index("ix_governance_tools_status", table_name="governance_tools")
    op.drop_index("ix_governance_tools_name", table_name="governance_tools")
    op.drop_index("ix_governance_tools_org_id", table_name="governance_tools")
    op.drop_table("governance_tools")
