"""Short-lived governed-tool delegation, signed by the gateway's RSA key.

Only the mediated governed-tools service calls this, and only after live run and
membership checks have resolved the tenant and the human server-side. The
governance gateway holds public verification keys only; it can verify an ADP
identity and never mint one.

## Why RS256 and not the Ed25519 envelope key

:mod:`src.agentauth.door_identity` signs with the Ed25519 envelope key because
its verifier is the Door, which we also own. This token's verifier is an external
AgentCore Gateway configured with a ``CUSTOM_JWT`` authorizer, which consumes an
OIDC discovery document and a JWKS. Ed25519/``EdDSA`` support there is not
something this repository can assert.

RSA avoids the question entirely, and the key already exists: the deployment
provisions ``adp/{env}/gateway-oidc-signing-key`` and
:mod:`src.auth.gitlab_sso` already publishes its public half as RFC 7517 JWKS at
``/.well-known/jwks.json`` -- an endpoint whose stated purpose is to make "the
signing identity reusable by future OIDC clients". This is that client. No new
key material is provisioned, and the envelope key keeps its single purpose.

## Why this is a JWT when the run credential deliberately is not

:mod:`src.agentauth.run_credential` documents at length why it is *not* a JWT: a
caller-supplied ``alg`` header is a negotiation surface, and it has exactly one
algorithm. That reasoning is intact and does not apply here. The verifier is
external and speaks OIDC; JWT is its wire format, not our choice. The protection
is on the other side of the boundary -- the authorizer pins the algorithm from
the published JWKS -- so we emit a fixed ``RS256`` header and never read one.

## What is bound, and what deliberately is not

``sub`` and the tenant claim are the values the caller may not choose. Both come
from a locked read of the authority tables performed by the mediation route
microseconds earlier, never from a worker header or the pod environment.

Deliberately absent: a ``body_sha256`` claim. :func:`sign_door_identity` binds
one because the Door verifies it. The governance gateway will not, and a claim
nothing checks is worse than no claim -- it reads as integrity protection that
is not there.

The ~60s TTL is load-bearing rather than hygienic. The tenant claim is a
*snapshot* of ``tenant_memberships``, which is the authority; a short life is
what keeps the snapshot honest and bounds the window in which a withdrawn
membership still presents as live.
"""

from __future__ import annotations

import os
import time
import uuid

import jwt

# Audience for governed tool calls. A dedicated value rather than a reused
# Cognito resource-server scope: the authorizer's audience check should mean
# "this token was minted for a governed tool call", not "this token was minted
# for something". A shared audience makes that check close to vacuous.
GOVERNED_TOOLS_AUDIENCE = "adp-governed-tools"

# The tenant claim name. `custom:org_id` IS the tenant id in ADP; there is no
# `custom:tenant_id` attribute anywhere in the Cognito module, and the reads of
# that name elsewhere in the tree all fall back to this one. Binding policy to a
# never-minted claim yields a policy that silently matches nothing, which looks
# identical to a working one until a cross-tenant call succeeds.
TENANT_CLAIM = "custom:org_id"

# `attributed_org_id` is deliberately not accepted here in any form: it is
# caller-influenced and `src/shared/schemas/auth.py` states it must never gate
# access. Routing it into an authorization claim would be a cross-tenant hole.

GOVERNED_TOOLS_TTL_SECONDS = 60

_SIGNING_ALGORITHM = "RS256"


class GovernedTokenError(Exception):
    """The governed-tools token could not be minted."""


def governed_tools_issuer(env: dict[str, str] | None = None) -> str:
    """Return the issuer this deployment advertises and signs under.

    One function so the discovery document and the signer cannot disagree. An
    issuer mismatch between them fails at the authorizer with no useful signal,
    because the token looks well-formed and the discovery document looks valid.
    """
    source = os.environ if env is None else env
    environment = source.get("BG_ENVIRONMENT", "dev")
    return f"urn:adp:gateway:{environment}"


def governed_tools_key_id(env: dict[str, str] | None = None) -> str:
    """Return the `kid` of the published signing key.

    Must match the `kid` that `src.auth.gitlab_sso`'s JWKS endpoint stamps on
    the public key, or the authorizer fetches a keyset in which it cannot find
    this token's key and refuses every call.
    """
    source = os.environ if env is None else env
    return f"adp-gateway-{source.get('BG_ENVIRONMENT', 'dev')}"


def mint_governed_tools_token(
    *,
    principal: str,
    tenant_id: str,
    owner_sub: str,
    private_key_pem: bytes,
    env: dict[str, str] | None = None,
) -> str:
    """Mint a short-lived RS256 JWT asserting a verified tenant and human.

    `tenant_id` and `owner_sub` must come from the caller's locked membership
    read, never from a worker-supplied header or the pod environment. `principal`
    is the run's own principal and is carried for audit attribution only.
    """
    if not principal or not tenant_id or not owner_sub:
        raise GovernedTokenError("governed tools signing identity unavailable")
    if not private_key_pem:
        raise GovernedTokenError("governed tools signing key unavailable")
    now = int(time.time())
    payload = {
        "iss": governed_tools_issuer(env),
        "aud": GOVERNED_TOOLS_AUDIENCE,
        # The verified human. Cedar may bind per-user policy to this; it is a
        # locked read of `users.cognito_sub`, not a login-time cache.
        "sub": owner_sub,
        TENANT_CLAIM: tenant_id,
        # Which run acted, for audit. Never an authorization input: a run
        # principal is not a tenant and must not be read as one.
        "principal": principal,
        "iat": now,
        "exp": now + GOVERNED_TOOLS_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
    }
    try:
        return jwt.encode(
            payload,
            private_key_pem,
            algorithm=_SIGNING_ALGORITHM,
            headers={"kid": governed_tools_key_id(env)},
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        # A key that will not load or will not sign. `jwt.PyJWTError` is listed
        # first and explicitly: PyJWT raises `InvalidKeyError` for an unparseable
        # PEM, and that derives from `Exception` directly rather than from
        # `ValueError`, so catching only the builtins lets it escape as a 500
        # where the caller intends a 503. The message can carry key material or
        # path detail, so it is not propagated.
        raise GovernedTokenError("governed tools token could not be signed") from exc
