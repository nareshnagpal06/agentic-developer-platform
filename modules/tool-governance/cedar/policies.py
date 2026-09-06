"""Generate Cedar policies from the governance config.

Cedar is the ENFORCEMENT control — it decides who may see and call each tool, and
it is the only thing in this architecture that actually gates access (the
registry does not). One policy is generated per tool, fencing it to the tool's
tenant.

ADP mapping
-----------
The standalone project fenced tools to a ``custom:tenant`` claim. In ADP the
tenant lives in ``custom:org_id`` (verified against ADP's Pre-Token-Generation
Lambda), so the principal is an ADP org. The Cedar entity model:

    ADP::Org::"<org_id>"     the tenant a caller belongs to (from custom:org_id)
    ADP::Tool::"<name>"      a governed tool
    Action::"invoke"         calling a tool
    Action::"list"           discovering a tool (tools/list)

A caller in org ``finance`` may invoke ``finance-reports`` because it is fenced
to ``finance``; the same caller never even SEES ``jira-search`` in tools/list
because no policy permits it — governance as absence, not refusal.

The negative case is the one that matters, and the standalone project learned it
the hard way: three Cedar syntaxes were found that validate, deploy, and enforce
NOTHING. The generated policies below use the ``principal in`` form that was
verified to actually filter tools/list against a live Gateway. Any change here
must be re-checked with a negative test (ask for the OTHER tenant's tool and
confirm it is absent), never just "does it deploy".
"""

from __future__ import annotations

from .. import config as cfg


def policy_for_tool(tool: cfg.Tool, gateway_arn: str) -> str:
    """One Cedar policy fencing a tool to its tenant.

    ``gateway_arn`` scopes the resource clause so the policy applies only to this
    Gateway's tools, not any tool of the same name elsewhere.
    """
    return (
        f"// {tool.name} — fenced to org {tool.tenant} (owner: {tool.owner or 'unknown'})\n"
        f"permit(\n"
        f'    principal in ADP::Org::"{tool.tenant}",\n'
        f"    action in [Action::\"invoke\", Action::\"list\"],\n"
        f'    resource == ADP::Tool::"{tool.name}"\n'
        f");"
    )


def generate_all(conf: cfg.Config, gateway_arn: str) -> dict[str, str]:
    """Return {tool_name: cedar_policy_text} for every tool that should be enforced.

    When ``registry.require_approval_to_enable`` is set, a caller is expected to
    pass the set of APPROVED tool names via ``approved_tools`` to
    :func:`generate_enforced` instead — this function generates for every tool in
    the config regardless of approval state (the baseline, deploy-time set).
    """
    return {t.name: policy_for_tool(t, gateway_arn) for t in conf.tools}


def generate_enforced(
    conf: cfg.Config, gateway_arn: str, approved_tools: set[str] | None = None
) -> dict[str, str]:
    """Return policies for tools that should actually be callable right now.

    If the registry requires approval to enable (the ADP enhancement), only tools
    whose names appear in ``approved_tools`` get a policy — so clicking "Approve"
    in the dashboard is what generates the policy and turns the tool on. Otherwise
    every configured tool gets a policy (standalone behaviour: approval is
    review-only, Cedar fences by tenant regardless).
    """
    gate_on_approval = bool(
        conf.registry and conf.registry.require_approval_to_enable
    )
    if not gate_on_approval:
        return generate_all(conf, gateway_arn)

    approved = approved_tools or set()
    return {
        t.name: policy_for_tool(t, gateway_arn)
        for t in conf.tools
        if t.name in approved
    }
