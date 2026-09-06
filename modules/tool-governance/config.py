"""Load and validate the governance config for ADP.

Adapted from the standalone AI-Governance-v2 config loader. The key differences
for ADP integration:

  * Identity comes from ADP's Cognito pool, and the tenant lives in the
    ``custom:org_id`` claim (verified against ADP's Pre-Token-Generation Lambda),
    not the standalone project's ``custom:tenant``.
  * The governance service runs IN ADP's account and validates ADP's tokens
    directly — there is no separate identity provider to stand up.

Validation is deliberately strict and fails loudly. The standalone build's
central defect was a ``.get()`` with a default that swallowed a wrong key name
and returned an empty result forever, so nothing here silently defaults a value
that must exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when the governance config is missing, unreadable, or invalid."""


# LOG_ONLY evaluates policies and records what *would* happen without enforcing.
# ENFORCE actually denies. There is no third value, and notably no DISABLED —
# to take a policy out of play you remove it.
ENFORCEMENT_MODES = ("LOG_ONLY", "ENFORCE")

# The interceptor's own modes. Deliberately different words from the policy
# engine's ENFORCEMENT_MODES: they are separate mechanisms with separate failure
# modes, and a shared "LOG_ONLY" spelled the same way would make a
# misconfiguration unreadable in a single log line.
SCAN_MODES = ("OBSERVE", "ENFORCE")


@dataclass(frozen=True)
class ToolArgument:
    name: str
    type: str
    description: str
    required: bool


@dataclass(frozen=True)
class Tool:
    """One governed tool.

    ``tenant`` maps to a Cedar policy that fences the tool to an ADP org.
    ``owner`` is who answers for it in the catalogue. ``handler`` names the
    backend the governance gateway routes to when the call is permitted.
    """

    name: str
    tenant: str
    handler: str
    description: str
    owner: str = ""
    arguments: list[ToolArgument] = field(default_factory=list)


@dataclass(frozen=True)
class CognitoConfig:
    """Points at ADP's existing Cognito pool.

    ``tenant_claim`` defaults to ``custom:org_id`` — ADP's verified tenant claim.
    The standalone project used ``custom:tenant``; that mapping is the one thing
    the integration must change, and it is a config value rather than code.
    """

    user_pool_id: str
    app_client_id: str
    tenant_claim: str = "custom:org_id"

    @property
    def discovery_url(self) -> str:
        region = self.user_pool_id.split("_", 1)[0]
        return (
            f"https://cognito-idp.{region}.amazonaws.com/"
            f"{self.user_pool_id}/.well-known/openid-configuration"
        )


@dataclass(frozen=True)
class RegistryConfig:
    """The catalogue. Optional — the gateway works without it.

    That is not a design compromise, it is what AgentCore does: there is no
    registry field on create-gateway or create-gateway-target, so a record is a
    documentation and review workflow, not an admission gate. The gateway never
    consults it — Cedar decides what is callable.

    ``require_approval_to_enable`` is the ADP enhancement: when true, a tool's
    Cedar policy is only generated once its registry record reaches APPROVED, so
    the reviewer's approval genuinely turns the tool on. Default false preserves
    the standalone behaviour (approval is review-only).
    """

    name: str
    auto_approval: bool = False
    reviewer_group: str = "platform-reviewers"
    require_approval_to_enable: bool = False


@dataclass(frozen=True)
class AdmissionScanConfig:
    """The prompt-injection scan, run by a Gateway request interceptor.

    Unlike the registry, this one IS in the request path — the gateway invokes
    the interceptor before the tool, and a refusal actually refuses.

        OBSERVE   scan, log the verdict, allow the call anyway
        ENFORCE   refuse a call whose content trips the scan

    ``fail_open`` decides what an unavailable scanner means. Default false: a
    scanner that cannot run blocks the call. Fail-open turns a Bedrock outage
    into a silent hole rather than a visible outage, so it is opt-in and named.
    """

    mode: str = "OBSERVE"
    fail_open: bool = False


@dataclass(frozen=True)
class Config:
    platform_name: str
    region: str
    cognito: CognitoConfig
    tenants: list[str]
    tools: list[Tool]
    enforcement_mode: str
    registry: RegistryConfig | None = None
    admission_scan: AdmissionScanConfig | None = None

    @property
    def policy_engine_name(self) -> str:
        """A policy engine name AgentCore will accept.

        PolicyEngineName must match ``^[A-Za-z][A-Za-z0-9_]*$`` — no hyphens. The
        platform name has them, so they become underscores.
        """
        return self.platform_name.replace("-", "_") + "_engine"


# --------------------------------------------------------------------------- #
# Loader
# --------------------------------------------------------------------------- #


def load(path: Path) -> Config:
    """Read the governance config and return a validated Config."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    platform = _require_mapping(raw, "platform")
    cognito_raw = _require_mapping(raw, "cognito")

    cognito = CognitoConfig(
        user_pool_id=_require_str(cognito_raw, "user_pool_id", "cognito"),
        app_client_id=_require_str(cognito_raw, "app_client_id", "cognito"),
        tenant_claim=cognito_raw.get("tenant_claim", "custom:org_id"),
    )

    tenants = [
        _require_str(t, "name", "tenants[]") for t in _require_list(raw, "tenants")
    ]

    tools = [_parse_tool(t, tenants) for t in _require_list(raw, "tools")]

    governance_raw = _require_mapping(raw, "governance")
    enforcement_mode = _require_str(governance_raw, "enforcement_mode", "governance")
    if enforcement_mode not in ENFORCEMENT_MODES:
        raise ConfigError(
            f"governance.enforcement_mode must be one of {ENFORCEMENT_MODES}, "
            f"got {enforcement_mode!r}"
        )

    registry = _parse_registry(raw.get("registry"))
    admission_scan = _parse_admission_scan(raw.get("admission_scan"))

    return Config(
        platform_name=_require_str(platform, "name", "platform"),
        region=_require_str(platform, "region", "platform"),
        cognito=cognito,
        tenants=tenants,
        tools=tools,
        enforcement_mode=enforcement_mode,
        registry=registry,
        admission_scan=admission_scan,
    )


def _parse_tool(raw: Any, tenants: list[str]) -> Tool:
    if not isinstance(raw, dict):
        raise ConfigError(f"each tool must be a mapping, got {type(raw).__name__}")

    name = _require_str(raw, "name", "tools[]")
    tenant = _require_str(raw, "tenant", f"tools[{name}]")
    if tenant not in tenants:
        raise ConfigError(
            f"tool {name!r} references tenant {tenant!r}, which is not declared "
            f"in the tenants list {tenants}"
        )

    arguments = []
    args_raw = raw.get("arguments") or {}
    if not isinstance(args_raw, dict):
        raise ConfigError(f"tool {name!r} arguments must be a mapping")
    for arg_name, arg_spec in args_raw.items():
        if not isinstance(arg_spec, dict):
            raise ConfigError(f"tool {name!r} argument {arg_name!r} must be a mapping")
        arguments.append(
            ToolArgument(
                name=arg_name,
                type=_require_str(arg_spec, "type", f"tools[{name}].arguments.{arg_name}"),
                description=arg_spec.get("description", ""),
                required=bool(arg_spec.get("required", False)),
            )
        )

    return Tool(
        name=name,
        tenant=tenant,
        handler=_require_str(raw, "handler", f"tools[{name}]"),
        description=_require_str(raw, "description", f"tools[{name}]"),
        owner=raw.get("owner", ""),
        arguments=arguments,
    )


def _parse_registry(raw: Any) -> RegistryConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("registry must be a mapping if present")
    return RegistryConfig(
        name=_require_str(raw, "name", "registry"),
        auto_approval=bool(raw.get("auto_approval", False)),
        reviewer_group=raw.get("reviewer_group", "platform-reviewers"),
        require_approval_to_enable=bool(raw.get("require_approval_to_enable", False)),
    )


def _parse_admission_scan(raw: Any) -> AdmissionScanConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("admission_scan must be a mapping if present")
    mode = raw.get("mode", "OBSERVE")
    if mode not in SCAN_MODES:
        raise ConfigError(
            f"admission_scan.mode must be one of {SCAN_MODES}, got {mode!r}"
        )
    return AdmissionScanConfig(
        mode=mode,
        fail_open=bool(raw.get("fail_open", False)),
    )


# --------------------------------------------------------------------------- #
# Strict getters — every one fails loudly rather than defaulting silently.
# --------------------------------------------------------------------------- #


def _require_mapping(raw: dict, key: str) -> dict:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"top-level {key!r} section is required and must be a mapping")
    return value


def _require_list(raw: dict, key: str) -> list:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"top-level {key!r} is required and must be a non-empty list")
    return value


def _require_str(raw: dict, key: str, ctx: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{ctx}.{key} is required and must be a non-empty string")
    return value
