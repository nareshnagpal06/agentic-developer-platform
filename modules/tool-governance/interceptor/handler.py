"""The request interceptor — the control that is actually in the call path.

This runs inside the AgentCore Gateway on every intercepted request, before the
tool is called. It scans the text of the call through Bedrock Guardrails looking
for prompt injection, and refuses the call if the scan trips.

Ported from the standalone AI-Governance-v2 project essentially unchanged — the
interceptor contract is a property of AgentCore, not of ADP, so the handler is
identical. The ADP-specific wiring (which Cognito pool, which tools) lives in the
config and the deployment, not here.

WHY THIS EXISTS ALONGSIDE THE REGISTRY

The registry is NOT in the request path: a record marked REJECTED does not stop a
tool being called. So "we scan tool descriptions at registration" is a review
control, not an enforcement one. This interceptor is the enforcement one — the
Gateway invokes it, and it can refuse.

THE CONTRACT (established by probing the live Gateway)

There is no {"action": "ALLOW"} field. The model is: return the request, or
short-circuit with a response.

    allow   {"interceptorOutputVersion": "1.0",
             "mcp": {"transformedGatewayRequest": {"body": <the JSON-RPC body>}}}
    refuse  {"interceptorOutputVersion": "1.0",
             "mcp": {"transformedGatewayResponse": {"statusCode": 403,
                                                    "body": <JSON-RPC error>}}}

Three traps:
  1. ALLOW IS NOT SILENCE. An empty mcp member passes envelope validation and
     then fails the request with -32700 "Parse error". An allow must echo the
     body back.
  2. THE OUTPUT KEYS ARE NOT THE INPUT KEYS. Input carries gatewayRequest;
     output must say transformedGatewayRequest.
  3. AN UNRECOGNISED KEY IS FATAL. Any unknown member inside mcp fails the whole
     response. So this handler returns exactly one shape and no speculative
     extras.

IDENTITY

There is NO structured identity in the interceptor event — no claims, no sub, no
tenant. The only identity available is the raw bearer token in headers, and only
if passRequestHeaders is true. So this control scans CONTENT and leaves IDENTITY
to Cedar, which does receive claims as entity tags. In ADP the tenant claim is
custom:org_id — but that matters to Cedar, not to this handler.

FAIL-CLOSED IS A DECISION

If Guardrails errors or times out, this blocks the call (FAIL_OPEN=false
default). Right posture for a security control; it means a Bedrock outage becomes
a tool outage, which is stated rather than buried.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Short read timeout, no retries. Guardrails measured ~106-128ms, and this call
# sits in the request path of every tool invocation — a slow scan is worse than a
# failed one, because it is charged to every user on every call.
bedrock = boto3.client(
    "bedrock-runtime",
    config=BotoConfig(read_timeout=5, connect_timeout=2, retries={"max_attempts": 1}),
)

GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")
MODE = os.environ.get("INTERCEPTOR_MODE", "OBSERVE").upper()
FAIL_OPEN = os.environ.get("FAIL_OPEN", "false").lower() == "true"

OUTPUT_VERSION = "1.0"

BLOCK_MESSAGE = (
    "Refused by the ADP governance admission scan: this request's content was "
    "flagged as a possible prompt-injection attempt."
)

# -32000 is the JSON-RPC "server error" range, what AWS's interceptor samples use
# for a refusal. Not -32600 (invalid request) — the request is well formed, it is
# simply not allowed.
REFUSAL_CODE = -32000

# Methods that legitimately carry nothing to scan. Enumerated rather than
# inferred: the difference between "this method has no arguments" and "the event
# shape changed and we can no longer find the arguments" is the difference
# between a working control and a decorative one, and they look identical unless
# one is a closed list.
ARGUMENTLESS_METHODS = frozenset(
    {
        "initialize",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
    }
)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Scan one intercepted request and decide whether it may proceed."""
    mcp = event.get("mcp") or {}
    request = mcp.get("gatewayRequest") or {}
    body = request.get("body") or {}
    method = body.get("method")

    # No interceptionPoint field exists; the presence of gatewayResponse is the
    # discriminator. This Gateway registers REQUEST only, so a response here means
    # the configuration changed and this handler has not caught up.
    if mcp.get("gatewayResponse") is not None:
        logger.warning(
            "RESPONSE interception point reached, which this handler does not "
            "implement — passing through. PROMPT_ATTACK is not evaluated on "
            "source=OUTPUT anyway. Remove RESPONSE from interception_points."
        )
        return _allow(body)

    scannable = _scannable_text(body)

    logger.info("method=%s mode=%s scannable_chars=%d", method, MODE, len(scannable))

    if not scannable:
        if method in ARGUMENTLESS_METHODS or method is None:
            logger.info("nothing to scan for method=%s — allowing", method)
        else:
            logger.warning(
                "no scannable text found for method=%s — allowing, but the scan "
                "did NOT run. If this persists the event shape has changed and "
                "_scannable_text needs updating.",
                method,
            )
        return _allow(body)

    verdict = _scan(scannable)

    if verdict["blocked"]:
        logger.warning(
            "ADMISSION SCAN BLOCKED method=%s reasons=%s latency_ms=%s mode=%s",
            method,
            verdict["reasons"],
            verdict["latency_ms"],
            MODE,
        )
        if MODE == "ENFORCE":
            return _refuse(body, verdict)
        logger.warning(
            "OBSERVE mode — the call is being ALLOWED THROUGH despite the block. "
            "Set INTERCEPTOR_MODE=ENFORCE to refuse."
        )
        return _allow(body)

    logger.info(
        "admission scan passed method=%s latency_ms=%s", method, verdict["latency_ms"]
    )
    return _allow(body)


# ------------------------------------------------------------------- scanning


def _scan(text: str) -> dict[str, Any]:
    """Run text through Guardrails. Returns a verdict, never raises.

    source=INPUT is not incidental. PROMPT_ATTACK is only evaluated on INPUT — a
    response-side scan using this filter would report clean forever.
    """
    if not GUARDRAIL_ID:
        logger.error("GUARDRAIL_ID is not set — cannot scan")
        return _scan_failure("guardrail not configured")

    try:
        response = bedrock.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VERSION,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
    except ClientError as exc:
        logger.exception("Guardrails call failed")
        return _scan_failure(f"guardrails error: {exc.response['Error']['Code']}")
    except Exception as exc:  # noqa: BLE001 — a timeout must not become a 500
        logger.exception("Guardrails call failed")
        return _scan_failure(f"guardrails unavailable: {type(exc).__name__}")

    assessments = response.get("assessments") or []
    latency = None
    if assessments:
        latency = (assessments[0].get("invocationMetrics") or {}).get(
            "guardrailProcessingLatency"
        )

    return {
        "blocked": response.get("action") == "GUARDRAIL_INTERVENED",
        "reasons": _reasons(assessments),
        "latency_ms": latency,
        "failed": False,
    }


def _scan_failure(why: str) -> dict[str, Any]:
    """What a scan that could not run means. Fail-closed by default."""
    return {
        "blocked": not FAIL_OPEN,
        "reasons": [f"scan could not run ({why})"],
        "latency_ms": None,
        "failed": True,
    }


def _reasons(assessments: list[dict]) -> list[str]:
    """Human-readable reasons, for the log line and the refusal message."""
    reasons: list[str] = []
    for assessment in assessments:
        for f in (assessment.get("contentPolicy") or {}).get("filters") or []:
            if f.get("detected"):
                reasons.append(f"{f.get('type')} ({f.get('confidence')} confidence)")
        for t in (assessment.get("topicPolicy") or {}).get("topics") or []:
            if t.get("detected"):
                reasons.append(f"denied topic: {t.get('name')}")
        for w in (assessment.get("wordPolicy") or {}).get("customWords") or []:
            if w.get("detected"):
                reasons.append(f"blocked word: {w.get('match')}")
    return reasons or ["flagged by Guardrails"]


# -------------------------------------------------------------- event reading


def _scannable_text(body: dict[str, Any]) -> str:
    """Everything in this request worth scanning, as one string.

    Scans the tool ARGUMENTS, not the tool description. The description is what a
    reviewer reads at publish time and is already scanned there. What reaches the
    model at RUN time, on every call, is the argument values — attacker-controlled
    in a way the registered description is not.
    """
    params = body.get("params") or {}
    parts: list[str] = []

    arguments = params.get("arguments")
    if isinstance(arguments, dict):
        parts.extend(_flatten(arguments))
    elif arguments is not None:
        parts.append(str(arguments))

    name = params.get("name")
    if name:
        parts.append(str(name))

    return "\n".join(p for p in parts if p.strip())


def _flatten(value: Any) -> list[str]:
    """Every string anywhere inside an argument value.

    Recurses into nested objects and lists — a scan that only reads the first
    level is trivially evaded by nesting the payload one deeper.
    """
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_flatten(v))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for v in value:
            out.extend(_flatten(v))
        return out
    if value is None:
        return []
    return [str(value)]


# ------------------------------------------------------------------ responses


def _allow(body: dict[str, Any]) -> dict[str, Any]:
    """Let the request through unchanged — by echoing it back.

    The body MUST be returned. An empty mcp member passes envelope validation and
    then fails the request with -32700 "Parse error", because the Gateway
    forwards the transformed request and there is nothing to forward. Allow is an
    action here, not an absence of one.

    Returning it unchanged is also the choice not to rewrite it: a governance
    control that silently alters a developer's call is harder to trust than one
    that refuses it out loud.
    """
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayRequest": {"body": body}},
    }


def _refuse(body: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any]:
    """Short-circuit the call with a JSON-RPC error, saying why.

    transformedGatewayResponse wins over transformedGatewayRequest, so returning
    it stops the call — the tool backend is never invoked.
    """
    reason = f"{BLOCK_MESSAGE} Reasons: {', '.join(verdict['reasons'])}."
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "body": {
                    "jsonrpc": "2.0",
                    # Echo the caller's id, not invent one. A JSON-RPC client
                    # matches responses to requests by id.
                    "id": body.get("id"),
                    "error": {"code": REFUSAL_CODE, "message": reason},
                },
            }
        },
    }
