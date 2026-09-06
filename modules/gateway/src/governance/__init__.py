"""Governance tool-registry module (gateway-side UI + API).

This package backs the "Governance" tab in the gateway admin UI. It stores a
catalogue of governed tools and their review status (PENDING/APPROVED/REJECTED)
so a reviewer can see what exists and (later) sign off.

Honest boundary: this registry is a REVIEW RECORD, not the enforcement gate. The
governance gateway's Cedar policies decide what is actually callable. Approving a
tool here is a human sign-off; it only becomes an enable-switch if the governance
module's `require_approval_to_enable` is turned on (a separate change).

Feature-flagged: the router is only exported (and thus mounted by app.py's
UNIT_MODULES auto-discovery) when GOVERNANCE_UI_ENABLED=true. Mirrors the
AGENT_CONTEXT_ENABLED gating on the knowledge module.
"""
