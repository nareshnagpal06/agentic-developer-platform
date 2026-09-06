"""Demo tool: finance-reports.

A governed tool for the `finance` tenant, used to prove enforcement end-to-end.
It returns canned data — the point is not the data, it's that Cedar decides
whether the caller may reach this Lambda at all, and the admission scan inspects
the arguments first.

The Gateway owns the tool schema (declared inline in the target), so this Lambda
is only ever invoked for tools/call — no tools/list branch needed.
"""

from __future__ import annotations

from typing import Any

_QUARTERLY = {
    "q1": {"revenue": 1_200_000, "opex": 800_000, "margin": 0.33},
    "q2": {"revenue": 1_450_000, "opex": 870_000, "margin": 0.40},
    "q3": {"revenue": 1_390_000, "opex": 910_000, "margin": 0.35},
    "q4": {"revenue": 1_610_000, "opex": 950_000, "margin": 0.41},
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Return a canned finance report for the requested quarter."""
    args = (event or {}).get("arguments") or event or {}
    quarter = str(args.get("quarter", "q1")).lower().strip()

    report = _QUARTERLY.get(quarter)
    if report is None:
        return {
            "error": f"Unknown quarter {quarter!r}. Try q1, q2, q3, or q4.",
        }

    return {
        "quarter": quarter,
        "revenue_usd": report["revenue"],
        "operating_expense_usd": report["opex"],
        "margin": report["margin"],
        "note": "Demo data from the finance-reports governed tool.",
    }
