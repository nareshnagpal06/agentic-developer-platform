"""Fixed-path governed-tools bridge; the bearer token stays in the gateway.

The agent pod holds no governance-gateway credential. It reaches a loopback
bridge, which SigV4-signs to this route; this route re-authenticates the run,
resolves the tenant and the human from the authority tables under a row lock,
mints a ~60s token from that locked read, and forwards the MCP request.

## Why mediation rather than vending a token to the worker

Agents run with ``Bash`` allowed under ``permissionMode: 'bypassPermissions'``,
so any credential present in the pod is reachable by model-directed code. A
vended token can be read and replayed; a mediated one never enters the process.
This is the same conclusion the Knowledge Door path reached -- ``getDoorAuthHeaders()``
returns ``{}`` and the worker holds no Door key -- and this module is a second
consumer of that mediation pattern rather than a parallel invention.

There is a second, duller argument. The worker's ``mcpServers`` config is built
once per run and never re-evaluated, so a vended short-TTL token would expire
mid-run with no refresh path. Mediation sidesteps it: the config holds only a
loopback URL.

## The difference from the Door path that matters

:mod:`src.agentauth.knowledge_service` forwards ``x-tenant-id``, ``x-github-login``
and ``x-owner-sub`` as *headers*, because the Door is an internal service sitting
behind a signed assertion that covers them.

This route must not. The governance gateway's Cedar policies read the tenant via
``principal.getTag()`` from verified token claims, so the tenant travels **only
inside the signed token**. Forwarding it as a header too would create a second,
unverified channel for the single most security-critical value in the system --
and a header is the channel an attacker can actually reach.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import Response

from src.agentauth.grants import AUTHORITY_SERVICE_POLICY
from src.agentauth.routes import AgentRuntime, get_agent_runtime, require_agent_transport
from src.agentauth.run_services import live_context
from src.shared.database import get_session_factory
from src.shared.models.onboarding import TenantMembership
from src.shared.models.organization import User

MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
SERVICE_TIMEOUT_SECONDS = 30

# `tools/list` and `tools/call` are both JSON-RPC methods on the single `/mcp/`
# path, so one entry governs both. An exact-match table with a 404 default is
# what stops the worker choosing a destination; a prefix or regex match here
# would reintroduce SSRF.
_PATHS = {("POST", "mcp/"): "/mcp/"}

router = APIRouter(
    prefix="/internal/v1/agent/self",
    tags=["agent-authority"],
    dependencies=[Depends(require_agent_transport)],
)


@asynccontextmanager
async def locked_governed_identity(record, grant):
    """Resolve tenant and human under a lock held through the forwarded call.

    The shared lock prevents membership removal or revocation from racing the
    request it authorizes. Worker headers and the pod environment are never
    inputs -- the only values that reach the token are read here, from the
    authority tables.

    A service root has no human identity and cannot borrow one: a governed tool
    call is attributed to a person, and `AUTHORITY_SERVICE_POLICY` has none.
    """
    if (
        grant.authority.kind == AUTHORITY_SERVICE_POLICY
        or grant.authority.org_id != record.tenant_id
        or grant.tenant_id != record.tenant_id
        or grant.principal != record.principal
    ):
        raise HTTPException(404, "not found")
    async with get_session_factory()() as db, db.begin():
        user = (
            await db.execute(
                select(User.cognito_sub)
                .join(TenantMembership, TenantMembership.user_id == User.id)
                .where(
                    User.id == grant.authority.human_id,
                    User.org_id == record.tenant_id,
                    User.user_kind == "human",
                    User.is_shadow.is_(False),
                    TenantMembership.tenant_id == record.tenant_id,
                    TenantMembership.is_active.is_(True),
                    TenantMembership.revoked_at.is_(None),
                )
                .with_for_update(read=True, of=(User, TenantMembership))
            )
        ).one_or_none()
        if user is None:
            raise HTTPException(404, "not found")
        # A token asserting a human must name one. An absent `cognito_sub` is a
        # provisioning gap, not a reason to mint a token with an empty subject
        # that policy would then have to decide how to read.
        if not user.cognito_sub:
            raise HTTPException(404, "not found")
        yield {"tenant_id": record.tenant_id, "owner_sub": user.cognito_sub}


async def bounded_body(request: Request) -> bytes:
    chunks = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            raise HTTPException(413, "governed tools request too large")
        chunks.append(chunk)
    return b"".join(chunks)


def governed_tools_config(runtime: AgentRuntime) -> str:
    """Return the operator-configured governed MCP endpoint, or refuse.

    Validated exactly as `door_config` validates the Door URL: an origin and
    nothing else. A path, query or fragment here would be silently prepended to
    the fixed path below; inline credentials would ship an operator secret
    upstream; a non-http scheme is not something `httpx` should be handed.
    """
    import os

    env = os.environ if runtime.env is None else runtime.env
    base = env.get("ADP_GOVERNED_TOOLS_URL", "").rstrip("/")
    parsed = urlsplit(base)
    if (
        not base
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise HTTPException(503, "governed tools service unavailable")
    return base


async def forward_governed(method: str, url: str, headers: dict[str, str], body: bytes) -> Response:
    # No worker-selected host, path, auth, proxy, cookie, session id or redirects.
    # `follow_redirects=False` keeps the bearer token from being replayed to a
    # relocation target; `trust_env=False` keeps a pod proxy variable from
    # putting an interceptor in front of it.
    async with httpx.AsyncClient(timeout=SERVICE_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
        async with client.stream(method, url, headers=headers, content=body) as upstream:
            if not 200 <= upstream.status_code < 300:
                # A refusal is a refusal. The upstream body can name policies,
                # tenants and tool catalogues the caller is not entitled to see,
                # and a Cedar denial is exactly the case where that matters.
                raise HTTPException(502, "governed tools request failed")
            chunks = []
            size = 0
            async for chunk in upstream.aiter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise HTTPException(502, "governed tools response too large")
                chunks.append(chunk)
            content_type = upstream.headers.get("content-type", "").split(";", 1)[0]
            if content_type not in {"application/json", "text/event-stream"} and upstream.status_code != 202:
                raise HTTPException(502, "governed tools response invalid")
            return Response(
                b"".join(chunks),
                status_code=upstream.status_code,
                media_type=content_type or None,
                headers={"Cache-Control": "no-store"},
            )


@router.api_route("/governed-tools/{path:path}", methods=["POST"])
async def own_governed_tools(path: str, request: Request, runtime: AgentRuntime = Depends(get_agent_runtime)) -> Response:
    target_path = _PATHS.get((request.method, path))
    if target_path is None or request.url.query:
        raise HTTPException(404, "not found")
    initial = await live_context(request, runtime)
    base = governed_tools_config(runtime)
    try:
        async with asyncio.timeout(SERVICE_TIMEOUT_SECONDS):
            body = await bounded_body(request)
            async with locked_governed_identity(initial[2], initial[3]) as identity:
                # Re-authenticate after the awaited membership read. No stale
                # credential or withdrawn grant becomes a signing authority
                # merely because it passed the first check before a slow query.
                current = await live_context(request, runtime)
                if initial[1:] != current[1:]:
                    raise HTTPException(404, "not found")
                from src.agentauth.governed_tools_token import (
                    GovernedTokenError,
                    mint_governed_tools_token,
                )

                try:
                    token = mint_governed_tools_token(
                        principal=current[3].principal,
                        tenant_id=identity["tenant_id"],
                        owner_sub=identity["owner_sub"],
                        private_key_pem=_signing_key_pem(),
                        env=runtime.env,
                    )
                except GovernedTokenError:
                    raise HTTPException(503, "governed tools identity unavailable") from None
                # The tenant is inside `token` and nowhere else. See module
                # docstring: no `x-tenant-id` header on this path, unlike the Door.
                headers = {
                    "authorization": f"Bearer {token}",
                    "content-type": "application/json",
                    "accept": "application/json, text/event-stream",
                }
                response = await forward_governed(request.method, base + target_path, headers, body)
                # Do not release tool output to a revoked/expired run after a
                # slow upstream call.
                final = await live_context(request, runtime)
                if current[1:] != final[1:]:
                    raise HTTPException(404, "not found")
                return response
    except (httpx.HTTPError, TimeoutError, SQLAlchemyError):
        raise HTTPException(503, "governed tools service unavailable") from None


def _signing_key_pem() -> bytes:
    """Load the deployment's RSA signing key PEM.

    Reuses `src.auth.gitlab_sso`'s loader so there is exactly one key, one
    Secrets Manager id, and one cache. A second loader would be a second place
    for the key to be stale or absent, and a `kid` published by one and signed
    by the other is a refusal with no useful signal.
    """
    from src.agentauth.governed_tools_token import GovernedTokenError
    from src.auth.gitlab_sso import _load_signing_key

    pem = _load_signing_key()
    if not pem:
        raise GovernedTokenError("governed tools signing key unavailable")
    return pem
