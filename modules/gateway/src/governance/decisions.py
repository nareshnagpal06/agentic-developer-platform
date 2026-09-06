"""Read policy-decision audit entries from the AgentCore decision log.

The AgentCore Gateway emits structured JSON to a CloudWatch log group
(APPLICATION_LOGS). Among those entries are "Policy evaluation completed" records
carrying the Cedar decision (ALLOW/DENY), the determining policies, the principal,
and latency — plus tools/call records that name the tool. This module reads those
back so the Governance UI's Audit tab shows who called what and whether it was
permitted.

Design:
  * Read-only, live query via CloudWatch Logs filter_log_events. No decisions are
    copied into Postgres — the log is the single source of truth (the same log we
    verified end-to-end).
  * The log group is env-configurable (GOVERNANCE_DECISION_LOG_GROUP). If unset or
    the group does not exist, this returns an empty result rather than erroring —
    the tab degrades to "no data" instead of 500.
  * Best-effort parsing: entries whose shape we do not recognise are skipped.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("bedrockgateway.governance.decisions")

# Default matches the deployed governance stack's vended-logs group. Override via
# env for other deployments.
_DEFAULT_LOG_GROUP = "/aws/vendedlogs/bedrock-agentcore/adp-governance/APPLICATION_LOGS"

# Hard cap on entries scanned/returned, to bound the query cost + response size.
_MAX_EVENTS = 500


def _log_group() -> str:
    return os.environ.get("GOVERNANCE_DECISION_LOG_GROUP", _DEFAULT_LOG_GROUP)


def _region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


def _parse_body(message: str) -> dict | None:
    """The vended log line is JSON with a nested ``body`` object. Return body or None."""
    try:
        outer = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        return None
    body = outer.get("body")
    return body if isinstance(body, dict) else None


def _decision_from_body(body: dict, ts_ms: int) -> dict | None:
    """Extract a decision record from a 'Policy evaluation completed' body, else None."""
    policy = body.get("policy")
    if not isinstance(policy, dict):
        return None
    decision = policy.get("decision")
    if not decision:
        return None

    principal = None
    p = policy.get("principal")
    if isinstance(p, dict):
        principal = p.get("entityId") or p.get("entity_id")

    determining = policy.get("determiningPolicies") or policy.get("determining_policies") or []
    if not isinstance(determining, list):
        determining = [str(determining)]

    return {
        "ts": datetime.fromtimestamp(ts_ms / 1000, tz=UTC),
        "decision": str(decision).upper(),
        "principal": principal,
        "tool": None,  # decision entries don't carry the tool name; joined below if present
        "determining_policies": [str(x) for x in determining],
        "latency_ms": policy.get("latencyMs") or policy.get("latency_ms"),
        "request_id": body.get("id") if isinstance(body.get("id"), str) else None,
    }


def _tool_from_body(body: dict) -> tuple[str | None, str | None]:
    """From a tools/call request body, return (request_id, tool_name) if present."""
    req = body.get("requestBody")
    tool_name = None
    req_id = body.get("id") if isinstance(body.get("id"), str) else None
    # requestBody is a stringified/loose JSON-ish structure in the vended logs;
    # try to pull the params.name out of it defensively.
    if isinstance(req, dict):
        params = req.get("params")
        if isinstance(params, dict):
            tool_name = params.get("name")
    elif isinstance(req, str) and "name=" in req:
        # Loose form like "{id=4, method=tools/call, params={name=repo-insights___...}}"
        try:
            frag = req.split("name=", 1)[1]
            tool_name = frag.split(",", 1)[0].split("}", 1)[0].strip()
        except Exception:  # noqa: BLE001 — best-effort tool-name extraction
            tool_name = None
    return req_id, tool_name


def get_decisions(
    *,
    since_ms: int | None,
    until_ms: int | None,
    decision_filter: str | None,
    tenant: str | None,
) -> tuple[list[dict], bool]:
    """Return (decisions, truncated) from the decision log within the time window.

    ``decision_filter`` (ALLOW/DENY) and ``tenant`` are applied after parsing.
    Tenant filtering is best-effort: the decision entry carries the principal's
    Cedar entity id, not the org_id directly, so tenant matching falls back to a
    substring match against determining-policy names (which are named
    "<tenant>_may_use_<tool>...").
    """
    client = boto3.client("logs", region_name=_region())
    kwargs: dict = {
        "logGroupName": _log_group(),
        "limit": _MAX_EVENTS,
    }
    if since_ms is not None:
        kwargs["startTime"] = since_ms
    if until_ms is not None:
        kwargs["endTime"] = until_ms

    try:
        events: list[dict] = []
        resp = client.filter_log_events(**kwargs)
        events.extend(resp.get("events", []))
        # Follow one page of nextToken at most to stay bounded.
        while resp.get("nextToken") and len(events) < _MAX_EVENTS:
            resp = client.filter_log_events(**kwargs, nextToken=resp["nextToken"])
            events.extend(resp.get("events", []))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            logger.info("Decision log group %s not found — returning empty", _log_group())
            return [], False
        logger.warning("filter_log_events failed: %s", exc)
        return [], False
    except Exception as exc:  # noqa: BLE001 — audit read must never 500 the tab
        logger.warning("Unexpected error reading decision log: %s", exc)
        return [], False

    # First pass: collect decisions and a request_id -> tool_name map.
    decisions: list[dict] = []
    tool_by_req: dict[str, str] = {}
    for ev in events:
        body = _parse_body(ev.get("message", ""))
        if not body:
            continue
        rec = _decision_from_body(body, ev.get("timestamp", 0))
        if rec:
            decisions.append(rec)
            continue
        req_id, tool = _tool_from_body(body)
        if req_id and tool:
            tool_by_req[req_id] = tool

    # Join tool names onto decisions by request_id where available.
    for rec in decisions:
        if rec.get("request_id") and rec["request_id"] in tool_by_req:
            rec["tool"] = tool_by_req[rec["request_id"]]

    # Apply filters.
    if decision_filter:
        want = decision_filter.upper()
        decisions = [d for d in decisions if d["decision"] == want]
    if tenant:
        decisions = [
            d
            for d in decisions
            if any(tenant in p for p in d["determining_policies"])
        ]

    # Newest first.
    decisions.sort(key=lambda d: d["ts"], reverse=True)
    truncated = len(events) >= _MAX_EVENTS
    return decisions, truncated
