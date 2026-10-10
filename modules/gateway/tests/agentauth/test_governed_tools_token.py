"""The token asserts only server-resolved identity, and says what it means."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.agentauth.governed_tools_discovery import well_known_router
from src.agentauth.governed_tools_token import (
    GOVERNED_TOOLS_AUDIENCE,
    GOVERNED_TOOLS_TTL_SECONDS,
    TENANT_CLAIM,
    GovernedTokenError,
    governed_tools_issuer,
    governed_tools_key_id,
    mint_governed_tools_token,
)

SIGNER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING_PEM = SIGNER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
PUBLIC_PEM = SIGNER.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

ENV = {"BG_ENVIRONMENT": "test"}
IDENTITY = {"principal": "agent-one", "tenant_id": "tenant-one", "owner_sub": "sub-one"}


def mint(**overrides) -> str:
    return mint_governed_tools_token(**{**IDENTITY, "private_key_pem": SIGNING_PEM, "env": ENV, **overrides})


def test_claims_carry_tenant_user_and_run():
    claims = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    assert claims[TENANT_CLAIM] == "tenant-one"
    assert claims["sub"] == "sub-one"
    assert claims["principal"] == "agent-one"
    assert claims["iss"] == "urn:adp:gateway:test"


def test_tenant_claim_is_org_id_and_nothing_else():
    # `custom:tenant_id` is never minted anywhere in ADP; binding policy to it
    # yields a policy that silently matches nothing. `attributed_org_id` is
    # caller-influenced and must never gate access. Neither may appear.
    assert TENANT_CLAIM == "custom:org_id"
    claims = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    assert "custom:tenant_id" not in claims
    assert "attributed_org_id" not in claims


def test_ttl_is_short_because_the_tenant_claim_is_a_membership_snapshot():
    claims = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    assert claims["exp"] - claims["iat"] == GOVERNED_TOOLS_TTL_SECONDS
    assert GOVERNED_TOOLS_TTL_SECONDS <= 60
    assert claims["exp"] > time.time()


def test_no_body_hash_claim_is_advertised():
    # sign_door_identity binds body_sha256 because the Door verifies it. The
    # governance gateway does not, and a claim nothing checks reads as integrity
    # protection that is not there.
    claims = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    assert "body_sha256" not in claims


def test_each_token_is_uniquely_identified():
    first = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    second = jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)
    assert first["jti"] != second["jti"]


def test_header_pins_rs256_and_the_published_kid():
    header = jwt.get_unverified_header(mint())
    assert header["alg"] == "RS256"
    # Must equal the kid src.auth.gitlab_sso's JWKS stamps on the public key.
    assert header["kid"] == governed_tools_key_id(ENV) == "adp-gateway-test"


def test_wrong_audience_is_rejected():
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(mint(), PUBLIC_PEM, algorithms=["RS256"], audience="adp-knowledge-door")


@pytest.mark.parametrize("field", ["principal", "tenant_id", "owner_sub"])
def test_missing_identity_refuses_rather_than_minting_a_blank_claim(field):
    with pytest.raises(GovernedTokenError):
        mint(**{field: ""})


def test_missing_key_refuses():
    with pytest.raises(GovernedTokenError):
        mint(private_key_pem=b"")


def test_unusable_key_refuses_without_leaking_detail():
    with pytest.raises(GovernedTokenError) as excinfo:
        mint(private_key_pem=b"-----BEGIN PRIVATE KEY-----\nnotakey\n-----END PRIVATE KEY-----\n")
    assert "notakey" not in str(excinfo.value)


def test_issuer_and_kid_default_without_environment():
    assert governed_tools_issuer({}) == "urn:adp:gateway:dev"
    assert governed_tools_key_id({}) == "adp-gateway-dev"


async def discovery_response(monkeypatch, base_url: str):
    import src.agentauth.governed_tools_discovery as module

    monkeypatch.setattr(module, "get_settings", lambda: type("S", (), {"gateway_base_url": base_url})())
    app = FastAPI()
    app.include_router(well_known_router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://gateway.test") as client:
        return await client.get("/.well-known/openid-configuration")


async def test_discovery_points_at_the_published_jwks(monkeypatch):
    response = await discovery_response(monkeypatch, "https://adp.example.com/")
    assert response.status_code == 200
    document = response.json()
    # The issuer must be the same string the signer emits, or the authorizer
    # refuses with no useful signal: both sides look individually well-formed.
    assert document["issuer"] == governed_tools_issuer()
    assert document["jwks_uri"] == "https://adp.example.com/.well-known/jwks.json"
    assert document["id_token_signing_alg_values_supported"] == ["RS256"]
    assert document["adp_governed_tools_audience"] == GOVERNED_TOOLS_AUDIENCE


async def test_discovery_mounts_prefix_free(monkeypatch):
    # A /.well-known/ path under a module prefix is not discoverable.
    assert all(route.path.startswith("/.well-known/") for route in well_known_router.routes)
    response = await discovery_response(monkeypatch, "https://adp.example.com")
    assert response.status_code == 200


async def test_discovery_refuses_when_no_public_origin_is_configured(monkeypatch):
    # Deriving jwks_uri from the Host header would let a caller choose where
    # verifiers fetch the key, which is the entire trust decision.
    response = await discovery_response(monkeypatch, "  ")
    assert response.status_code == 503
    assert "jwks_uri" not in response.text
