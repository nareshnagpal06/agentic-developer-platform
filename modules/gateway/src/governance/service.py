"""Data access for the governance tool-registry.

Uses SQLAlchemy ORM against the gateway DB (governance_tools lives here), which is
the idiomatic gateway pattern for gateway-owned tables. Read-only for step 1
(list + detail + count); approve/reject mutations are added in step 2.
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.governance.models import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    GovernanceTool,
)
from src.governance.schemas import GovernanceToolResponse, ToolSpec
from src.shared.models.base import utcnow

logger = logging.getLogger("bedrockgateway.governance.service")


def _to_response(row: GovernanceTool) -> GovernanceToolResponse:
    """Map an ORM row to the API response shape."""
    return GovernanceToolResponse(
        id=row.id,
        name=row.name,
        tenant=row.org_id,
        owner=row.owner or "",
        handler=row.handler or "",
        description=row.description or "",
        status=row.status,
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        reject_reason=row.reject_reason,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def list_tools(
    db: AsyncSession,
    *,
    tenant: str | None,
    status: str | None,
    page: int,
    page_size: int,
) -> tuple[list[GovernanceToolResponse], int]:
    """Return (items, total) for the registry, filtered + paginated.

    Platform-admin view: all tenants unless ``tenant`` is given. (Tenant-scoping
    for non-admin reviewers is handled at the route layer in a later step; step 1
    is admin-only, so this lists across tenants by default.)
    """
    conditions = []
    if tenant:
        conditions.append(GovernanceTool.org_id == tenant)
    if status:
        conditions.append(GovernanceTool.status == status)

    count_stmt = select(func.count()).select_from(GovernanceTool)
    for c in conditions:
        count_stmt = count_stmt.where(c)
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * page_size
    rows_stmt = select(GovernanceTool)
    for c in conditions:
        rows_stmt = rows_stmt.where(c)
    rows_stmt = (
        rows_stmt.order_by(GovernanceTool.created_at.desc())
        .limit(page_size)
        .offset(offset)
    )
    rows = (await db.execute(rows_stmt)).scalars().all()

    return [_to_response(r) for r in rows], total


async def get_tool(db: AsyncSession, tool_id: str) -> GovernanceToolResponse | None:
    """Fetch one tool by id, or None if not found."""
    row = (
        await db.execute(select(GovernanceTool).where(GovernanceTool.id == tool_id))
    ).scalar_one_or_none()
    return _to_response(row) if row else None


# ---------------------------------------------------------------------------
# Review actions — approve / reject (with audit sign-off)
# ---------------------------------------------------------------------------


async def _write_audit(
    db: AsyncSession,
    *,
    org_id: str,
    user_id: str,
    action: str,
    tool_id: str,
    old_status: str,
    new_status: str,
    reason: str | None,
    client_ip: str | None,
) -> None:
    """Record a review sign-off in the admin audit log.

    Imported lazily so this module has no import-time coupling to admin models.
    Best-effort: an audit-write failure must not fail the review action itself.
    """
    try:
        from src.admin.models import AuditLog

        db.add(
            AuditLog(
                org_id=org_id,
                user_id=user_id,
                action=action,
                resource_type="governance_tool",
                resource_id=tool_id,
                old_value={"status": old_status},
                new_value={"status": new_status, "reason": reason},
                client_ip=client_ip,
            )
        )
    except Exception:  # noqa: BLE001 — audit is best-effort, never blocks review
        logger.warning("Failed to write governance audit row for tool %s", tool_id, exc_info=True)


async def review_tool(
    db: AsyncSession,
    *,
    tool_id: str,
    approve: bool,
    reviewer_id: str,
    reason: str | None,
    client_ip: str | None,
) -> GovernanceToolResponse | None:
    """Set a tool APPROVED or REJECTED, stamp reviewer + time, write an audit row.

    Returns the updated tool, or None if the tool does not exist.
    """
    row = (
        await db.execute(select(GovernanceTool).where(GovernanceTool.id == tool_id))
    ).scalar_one_or_none()
    if row is None:
        return None

    old_status = row.status
    new_status = STATUS_APPROVED if approve else STATUS_REJECTED
    row.status = new_status
    row.reviewed_by = reviewer_id
    row.reviewed_at = utcnow()
    row.reject_reason = None if approve else (reason or "")

    # Commit the review status FIRST, on its own. The audit write is best-effort
    # and must never abort the review — if it shared this transaction and failed
    # (e.g. the audit_logs table is absent in an environment), the poisoned
    # transaction would roll back the status change too. So commit here, then
    # attempt the audit separately below.
    await db.commit()
    await db.refresh(row)
    result = _to_response(row)

    # Best-effort audit in an isolated transaction. Any failure (missing table,
    # etc.) is swallowed after a rollback so it cannot affect the review result.
    try:
        await _write_audit(
            db,
            org_id=row.org_id,
            user_id=reviewer_id,
            action="approve_tool" if approve else "reject_tool",
            tool_id=tool_id,
            old_status=old_status,
            new_status=new_status,
            reason=None if approve else reason,
            client_ip=client_ip,
        )
        await db.commit()
    except Exception:  # noqa: BLE001 — audit is best-effort, never blocks review
        logger.warning(
            "Governance audit write failed for tool %s — review still applied",
            tool_id,
            exc_info=True,
        )
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            pass

    return result


# ---------------------------------------------------------------------------
# Seeding / sync — populate the registry from the governance config
# ---------------------------------------------------------------------------


async def sync_tools(db: AsyncSession, tools: list[ToolSpec]) -> tuple[int, int, int]:
    """Upsert the registry from a list of governed tools. Returns (created, updated, total).

    Idempotent and review-safe:
      * A tool new to the registry is inserted with status = PENDING.
      * An existing tool (matched on tenant + name) has its descriptive fields
        (owner, handler, description) refreshed, but its review status is LEFT
        UNTOUCHED — re-syncing must never silently un-approve or un-reject a tool.
      * Tools removed from the config are NOT deleted here (a removed tool losing
        its Cedar policy is the real de-provisioning; leaving the catalogue row is
        the safer default and preserves its audit history).
    """
    created = 0
    updated = 0
    for spec in tools:
        existing = (
            await db.execute(
                select(GovernanceTool).where(
                    GovernanceTool.org_id == spec.tenant,
                    GovernanceTool.name == spec.name,
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            db.add(
                GovernanceTool(
                    org_id=spec.tenant,
                    name=spec.name,
                    owner=spec.owner or "",
                    handler=spec.handler or "",
                    description=spec.description or "",
                    status=STATUS_PENDING,
                )
            )
            created += 1
        else:
            # Refresh descriptive fields only; preserve status + review metadata.
            existing.owner = spec.owner or ""
            existing.handler = spec.handler or ""
            existing.description = spec.description or ""
            updated += 1

    await db.commit()
    total = (
        await db.execute(select(func.count()).select_from(GovernanceTool))
    ).scalar() or 0
    return created, updated, total


def load_tools_from_config_file() -> list[ToolSpec] | None:
    """Read tool specs from a governance.yaml if GOVERNANCE_CONFIG_PATH is set.

    Optional convenience path for local/in-repo use. In a deployed gateway the
    tool-governance module's files are not present, so the deploy-time push
    (POST /tools/sync with an explicit body) is the primary seeding path and this
    returns None when the env var is unset or the file is missing/invalid.
    """
    path = os.environ.get("GOVERNANCE_CONFIG_PATH")
    if not path or not os.path.isfile(path):
        return None
    # Lazy import: PyYAML is not a guaranteed gateway dependency, and this
    # config-file path is only a local/in-repo convenience — the primary seed
    # path is the POST body. Degrade gracefully if PyYAML is absent.
    try:
        import yaml
    except ImportError:
        logger.warning(
            "GOVERNANCE_CONFIG_PATH set but PyYAML is not installed — "
            "use the POST /tools/sync body to seed instead."
        )
        return None
    try:
        with open(path) as fh:
            raw = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("Could not read GOVERNANCE_CONFIG_PATH=%s: %s", path, exc)
        return None

    specs: list[ToolSpec] = []
    for t in raw.get("tools") or []:
        if not isinstance(t, dict) or not t.get("name") or not t.get("tenant"):
            continue
        specs.append(
            ToolSpec(
                name=str(t["name"]),
                tenant=str(t["tenant"]),
                owner=str(t.get("owner", "")),
                handler=str(t.get("handler", "")),
                description=str(t.get("description", "")).strip(),
            )
        )
    return specs
