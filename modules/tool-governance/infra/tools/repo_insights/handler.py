"""Demo tool: repo-insights.

A governed tool fenced to the `nareshnagpal06` tenant — the tenant a real ADP
agent runs as (from its custom:org_id). This is the tool that proves the
end-to-end integration: when an ADP agent is triggered, it should see this tool
as `mcp__governance__repo-insights` and be able to call it THROUGH the governance
gateway (Cedar permits it because the agent's org_id matches).

Returns canned insights — the point is that the call flows through governance
(auth + Cedar + scan + audit), not the data itself.
"""

from __future__ import annotations

from typing import Any


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return lightweight insights for a repository."""
    args = (event or {}).get("arguments") or event or {}
    repo = str(args.get("repo", "unknown")).strip()

    return {
        "repo": repo,
        "summary": f"'{repo}' is a small repository. Insights are demo data served "
        "through the ADP governance gateway.",
        "suggested_actions": [
            "Add a README if one is missing",
            "Check for a CI workflow",
            "Look for open issues labeled 'developer'",
        ],
        "note": "Demo data from the repo-insights governed tool (tenant nareshnagpal06).",
    }
