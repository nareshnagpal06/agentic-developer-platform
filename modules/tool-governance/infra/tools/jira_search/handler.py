"""Demo tool: jira-search.

A governed tool for the `engineering` tenant, used to prove tenant isolation:
a finance caller must NOT be able to see or call this, and an engineering caller
must NOT be able to see or call finance-reports. Returns canned data.

The Gateway owns the tool schema, so this Lambda is only invoked for tools/call.
"""

from __future__ import annotations

from typing import Any

_ISSUES = [
    {"key": "ENG-101", "summary": "Fix flaky auth integration test", "status": "In Progress"},
    {"key": "ENG-102", "summary": "Upgrade Node runtime to 22", "status": "Done"},
    {"key": "ENG-103", "summary": "Add retry with backoff to the API client", "status": "Open"},
    {"key": "ENG-104", "summary": "Investigate memory leak in worker pool", "status": "Open"},
]


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return Jira issues matching a keyword (case-insensitive substring)."""
    args = (event or {}).get("arguments") or event or {}
    query = str(args.get("query", "")).lower().strip()

    if not query:
        matches = _ISSUES
    else:
        matches = [
            i
            for i in _ISSUES
            if query in i["summary"].lower() or query in i["key"].lower()
        ]

    return {
        "query": query,
        "count": len(matches),
        "issues": matches,
        "note": "Demo data from the jira-search governed tool.",
    }
