"""OIDC discovery for the governed-tools signing identity.

AgentCore Gateway's ``CUSTOM_JWT`` inbound authorizer is configured with a
*discovery URL*, not a JWKS URL: it fetches
``/.well-known/openid-configuration`` and follows ``jwks_uri`` from there. ADP
already serves the JWKS (:mod:`src.auth.gitlab_sso`) but has never served the
document that points at it, so this is the one genuinely new artifact the
governed-tools integration needs on the identity side.

Public and unauthenticated, like every discovery document and like ADP's
existing ``/.well-known/cognito-config``. Nothing here is secret: it names an
issuer and the URL of a public keyset. Authenticating it would also break the
consumer, which fetches it before it holds any token at all.

Mounted via ``well_known_router`` so it lands at the host root rather than
inheriting a module prefix -- a ``/.well-known/`` path under a prefix is not a
discovery document any client will find.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from starlette.responses import JSONResponse

from src.agentauth.governed_tools_token import (
    GOVERNED_TOOLS_AUDIENCE,
    governed_tools_issuer,
)
from src.shared.config import get_settings

# Prefix-free: see module docstring. `app.py` includes this under the name
# `well_known_router` precisely so it does not inherit a prefix.
well_known_router = APIRouter(tags=["agent-authority"])

# Advertised as a courtesy to a strict consumer; this deployment is not a
# general-purpose OIDC provider and has no authorization or token endpoint.
_RESPONSE_TYPES = ["id_token"]
_SUBJECT_TYPES = ["public"]
_SIGNING_ALGORITHMS = ["RS256"]


@well_known_router.get(
    "/.well-known/openid-configuration",
    summary="OIDC discovery document for the governed-tools signing identity",
    description=(
        "Public, unauthenticated OIDC discovery for the identity ADP signs "
        "governed tool-call tokens under. Consumed by the AgentCore Gateway "
        "CUSTOM_JWT authorizer, which is configured with a discovery URL and "
        "follows `jwks_uri` from this document to fetch the public key."
    ),
    responses={
        200: {"description": "Discovery document returned"},
        503: {"description": "This deployment has no configured public origin"},
    },
)
async def openid_configuration() -> JSONResponse:
    """Return the OIDC discovery document for governed-tool tokens."""
    # The public origin must be configured, because `jwks_uri` has to be an
    # absolute URL a remote authorizer can resolve. Deriving it from the request
    # Host header instead would let a caller choose the key location that
    # verifiers are sent to, which is the whole trust decision.
    base = (get_settings().gateway_base_url or "").strip().rstrip("/")
    if not base:
        raise HTTPException(503, "governed tools discovery unavailable")
    return JSONResponse(
        {
            "issuer": governed_tools_issuer(),
            # Served by src.auth.gitlab_sso, which publishes this deployment's
            # RSA public key as RFC 7517 JWKS. One key, one `kid`, two consumers.
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": _SIGNING_ALGORITHMS,
            "response_types_supported": _RESPONSE_TYPES,
            "subject_types_supported": _SUBJECT_TYPES,
            "claims_supported": ["iss", "aud", "sub", "exp", "iat", "jti"],
            # Advertised so an operator configuring the authorizer can read the
            # expected audience off the deployment rather than from a document.
            "adp_governed_tools_audience": GOVERNED_TOOLS_AUDIENCE,
        },
        # Short and public. The keyset itself is cached for 300s by its own
        # endpoint; a long cache here would outlive an issuer change.
        headers={"Cache-Control": "public, max-age=300"},
    )
