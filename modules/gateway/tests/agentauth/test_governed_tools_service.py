"""Exercise the real HTTP bridge: worker headers cannot select another tenant."""

from contextlib import asynccontextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException

from src.agentauth import governed_tools_service as service
from src.agentauth.execution import ExecutionStateError
from src.agentauth.governed_tools_token import GOVERNED_TOOLS_AUDIENCE, TENANT_CLAIM
from src.agentauth.routes import get_agent_runtime, require_agent_transport
from tests.agentauth.test_run_services import GRANT, HEADERS, RECORD

SIGNER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SIGNING_PEM = SIGNER.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
PUBLIC_PEM = SIGNER.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

URL = "/internal/v1/agent/self/governed-tools/mcp/"
OWNER_SUB = "00000000-0000-0000-0000-000000000001"


def decode(token: str) -> dict:
    return jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)


@pytest.fixture
async def bridge(monkeypatch):
    context = (SimpleNamespace(uid="pod-one"), "caller", RECORD, GRANT)
    runtime = SimpleNamespace(
        env={"ADP_GOVERNED_TOOLS_URL": "https://governance.internal", "BG_ENVIRONMENT": "test"},
        authenticate=Mock(return_value=context),
        validate_flow=AsyncMock(),
    )
    identity_calls = []

    @asynccontextmanager
    async def identity(record, grant):
        identity_calls.append((record, grant))
        yield {"tenant_id": "tenant-one", "owner_sub": OWNER_SUB}

    monkeypatch.setattr(service, "locked_governed_identity", identity)
    monkeypatch.setattr(service, "_signing_key_pem", lambda: SIGNING_PEM)
    upstream_requests = []

    def upstream(request):
        upstream_requests.append(request)
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "result": {"content": ["own-tenant-data"]}},
            headers={"Set-Cookie": "secret-cookie"},
        )

    real_client = httpx.AsyncClient
    factory = Mock(side_effect=lambda **kwargs: real_client(transport=httpx.MockTransport(upstream), **kwargs))
    monkeypatch.setattr(service, "httpx", SimpleNamespace(AsyncClient=factory, HTTPError=httpx.HTTPError))
    app = FastAPI()
    app.include_router(service.router)
    app.dependency_overrides[get_agent_runtime] = lambda: runtime
    app.dependency_overrides[require_agent_transport] = lambda: None
    async with real_client(transport=httpx.ASGITransport(app=app), base_url="https://gateway.test") as client:
        yield SimpleNamespace(client=client, runtime=runtime, upstream=upstream_requests, factory=factory, identities=identity_calls)


async def test_caller_cannot_forward_auth_or_another_tenants_identity(bridge):
    hostile = {
        **HEADERS,
        "X-Tenant-Id": "victim",
        "X-Owner-Sub": "victim",
        "Authorization": "Bearer attacker-minted",
        "X-Internal-Api-Key": "worker-key",
        "Cookie": "victim-session",
        "Mcp-Session-Id": "victim-session",
        "Host": "attacker.test",
    }
    response = await bridge.client.post(URL, headers=hostile, json={"method": "tools/list"})
    assert response.status_code == 200
    (request,) = bridge.upstream
    assert str(request.url) == "https://governance.internal/mcp/"
    claims = decode(request.headers["authorization"].removeprefix("Bearer "))
    # The tenant and the human come from the locked read, never the headers.
    assert claims[TENANT_CLAIM] == RECORD.tenant_id
    assert claims["sub"] == OWNER_SUB
    assert claims["principal"] == GRANT.principal
    # The tenant travels ONLY inside the signed token. Unlike the Door path there
    # is no header channel for it, because Cedar reads verified claims and a
    # second unverified channel for the tenant would defeat that.
    for name in ("x-tenant-id", "x-owner-sub", "x-adp-run-service", "x-internal-api-key", "x-github-login"):
        assert name not in request.headers
    for name in ("x-adp-run-credential", "x-adp-workload-token", "cookie", "mcp-session-id"):
        assert name not in request.headers
    assert bridge.identities == [(RECORD, GRANT)]
    assert bridge.factory.call_args.kwargs == {"timeout": 30, "follow_redirects": False, "trust_env": False}
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"] == "no-store"


async def test_minted_token_is_short_lived_and_audience_bound(bridge):
    await bridge.client.post(URL, headers=HEADERS, json={})
    (request,) = bridge.upstream
    token = request.headers["authorization"].removeprefix("Bearer ")
    claims = decode(token)
    assert claims["aud"] == GOVERNED_TOOLS_AUDIENCE
    assert claims["iss"] == "urn:adp:gateway:test"
    # The TTL bounds how long a withdrawn membership still presents as live.
    assert 0 < claims["exp"] - claims["iat"] <= 60
    assert claims["jti"]
    # The kid must match what the JWKS endpoint publishes, or the authorizer
    # fetches a keyset it cannot find this key in and refuses every call.
    assert jwt.get_unverified_header(token)["kid"] == "adp-gateway-test"
    assert jwt.get_unverified_header(token)["alg"] == "RS256"


async def test_token_is_not_verifiable_with_an_unrelated_key(bridge):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    await bridge.client.post(URL, headers=HEADERS, json={})
    (request,) = bridge.upstream
    token = request.headers["authorization"].removeprefix("Bearer ")
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, other_pem, algorithms=["RS256"], audience=GOVERNED_TOOLS_AUDIENCE)


@pytest.mark.parametrize(
    "path",
    ["mcp", "mcp/?tenant=victim", "call", "tools", "mcp/victim", "../secrets", ""],
)
async def test_only_fixed_paths_without_query_are_reachable(bridge, path):
    response = await bridge.client.post("/internal/v1/agent/self/governed-tools/" + path, headers=HEADERS, json={})
    assert response.status_code == 404
    assert not bridge.upstream


@pytest.mark.parametrize("missing", list(HEADERS))
async def test_both_run_and_pod_proofs_are_required(bridge, missing):
    response = await bridge.client.post(URL, headers={k: v for k, v in HEADERS.items() if k != missing}, json={})
    assert response.status_code == 404
    assert not bridge.upstream
    assert not bridge.identities


@pytest.mark.parametrize("when", ["upload", "identity", "query"])
async def test_revocation_at_slow_boundaries_refuses(bridge, monkeypatch, when):
    if when == "upload":

        async def body():
            yield b'{"method":"tools/list"}'
            bridge.runtime.authenticate.side_effect = ExecutionStateError("revoked")
    else:

        async def body():
            yield b"{}"

        if when == "identity":

            @asynccontextmanager
            async def identity(*_):
                bridge.runtime.authenticate.side_effect = ExecutionStateError("revoked")
                yield {"tenant_id": "tenant-one", "owner_sub": OWNER_SUB}

            monkeypatch.setattr(service, "locked_governed_identity", identity)
        else:
            original = service.forward_governed

            async def forward(*args):
                response = await original(*args)
                bridge.runtime.authenticate.side_effect = ExecutionStateError("revoked")
                return response

            monkeypatch.setattr(service, "forward_governed", forward)
    response = await bridge.client.post(URL, headers=HEADERS, content=body())
    assert response.status_code == 404
    # Tool output must not reach a run that was revoked while it was awaited.
    assert "own-tenant-data" not in response.text
    assert len(bridge.upstream) == (1 if when == "query" else 0)


async def test_changed_authority_is_not_reused_after_body(bridge):
    first = bridge.runtime.authenticate.return_value
    changed = (*first[:3], replace(GRANT, revocation_epoch=2))
    bridge.runtime.authenticate.side_effect = [first, first, changed, changed]
    response = await bridge.client.post(URL, headers=HEADERS, json={})
    assert response.status_code == 404
    assert not bridge.upstream


async def test_identity_refusal_does_not_mint_a_token(bridge, monkeypatch):
    @asynccontextmanager
    async def refused(*_):
        raise HTTPException(404, "not found")
        yield  # pragma: no cover

    monkeypatch.setattr(service, "locked_governed_identity", refused)
    response = await bridge.client.post(URL, headers=HEADERS, json={})
    assert response.status_code == 404
    assert not bridge.upstream


async def test_oversized_request_is_refused_before_forwarding(bridge):
    async def body():
        yield b"x" * (service.MAX_REQUEST_BYTES + 1)

    response = await bridge.client.post(URL, headers=HEADERS, content=body())
    assert response.status_code == 413
    assert not bridge.upstream


async def test_upstream_refusal_body_is_not_relayed(bridge, monkeypatch):
    def upstream(request):
        # A Cedar denial names the policy and may name tools the caller is not
        # entitled to know exist.
        return httpx.Response(403, json={"error": "denied by policy tenant-two-only"})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        service,
        "httpx",
        SimpleNamespace(
            AsyncClient=lambda **kwargs: real_client(transport=httpx.MockTransport(upstream), **kwargs),
            HTTPError=httpx.HTTPError,
        ),
    )
    response = await bridge.client.post(URL, headers=HEADERS, json={})
    assert response.status_code == 502
    assert "tenant-two-only" not in response.text


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://governance.internal",
        "https://user:pw@governance.internal",
        "https://governance.internal/mcp/",
        "https://governance.internal?x=1",
        "https://governance.internal#f",
    ],
)
async def test_endpoint_must_be_a_bare_origin(bridge, url):
    bridge.runtime.env["ADP_GOVERNED_TOOLS_URL"] = url
    response = await bridge.client.post(URL, headers=HEADERS, json={})
    assert response.status_code == 503
    assert not bridge.upstream


async def test_non_post_methods_are_unroutable(bridge):
    for method in ("GET", "PUT", "DELETE", "PATCH"):
        response = await bridge.client.request(method, URL, headers=HEADERS)
        assert response.status_code == 405, method
    assert not bridge.upstream
