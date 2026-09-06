#!/usr/bin/env python3
"""CDK entry point for the ADP Tool Governance stack.

Reads ../governance.yaml (via the module's existing config loader) and deploys
the governance gateway: an AgentCore Gateway fronted by Cedar authorization and a
Bedrock Guardrails admission scan, pointed at ADP's Cognito pool.

This is an INDEPENDENT stack, deployed on its own into ADP's account — it is not
part of ADP's Terraform lifecycle. ADP's agents call the resulting gateway URL as
an MCP server (Pattern A, in-path). See ../README.md and
docs/design-governance-layer.md.
"""

import sys
from pathlib import Path

# The module root (parent of infra/) holds config.py, cedar/, interceptor/.
MODULE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MODULE_ROOT))

import aws_cdk as cdk  # noqa: E402

import config as gov_config  # noqa: E402  (the module's existing loader)
from infra.governance_stack import GovernanceStack  # noqa: E402


def main() -> None:
    try:
        conf = gov_config.load(MODULE_ROOT / "governance.yaml")
    except gov_config.ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    app = cdk.App()
    GovernanceStack(
        app,
        "AdpToolGovernance",
        config=conf,
        env=cdk.Environment(region=conf.region),
        description="ADP Tool Governance — governed MCP endpoint (Cedar + Guardrails)",
    )
    app.synth()


if __name__ == "__main__":
    main()
