#!/usr/bin/env bash
# =============================================================================
# Deploy the ADP Tool Governance stack (CDK) into the current AWS account.
#
# This is an INDEPENDENT stack — not part of ADP's Terraform lifecycle. It
# deploys the governed MCP gateway (AgentCore Gateway + Cedar + Guardrails)
# pointed at ADP's Cognito pool (values in governance.yaml).
#
# Prereqs:
#   - AWS creds for the target account (export AWS_PROFILE / AWS_REGION)
#   - Node + the CDK CLI (npm install -g aws-cdk)
#   - Python 3.12+
#   - governance.yaml filled with the target account's Cognito pool + client
#
# Usage:
#   export AWS_PROFILE=<profile> AWS_REGION=us-east-1
#   ./deploy.sh            # synth + deploy
#   ./deploy.sh --synth    # synth only (no deploy) — safe dry run
#   ./deploy.sh --destroy  # tear the stack down
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$HERE/infra"
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1

MODE="deploy"
case "${1:-}" in
  --synth)   MODE="synth" ;;
  --destroy) MODE="destroy" ;;
  "")        MODE="deploy" ;;
  *) echo "Unknown option: $1 (use --synth or --destroy)"; exit 2 ;;
esac

cd "$INFRA_DIR"

# 1. Python venv with CDK libs
if [ ! -d .venv ]; then
  echo "Creating venv + installing CDK libs..."
  python3 -m venv .venv
  .venv/bin/pip install --quiet -r requirements.txt
fi

# 2. Sanity: CDK CLI present
if ! command -v cdk >/dev/null 2>&1; then
  echo "ERROR: cdk CLI not found. Install with: npm install -g aws-cdk" >&2
  exit 1
fi

# 3. Run
case "$MODE" in
  synth)
    echo "Synthesizing (no deploy)..."
    cdk synth
    ;;
  deploy)
    echo "Bootstrapping CDK (idempotent) + deploying..."
    cdk bootstrap 2>/dev/null || true
    cdk deploy --require-approval never
    echo ""
    echo "Done. Set GOVERNANCE_MCP_URL on the agent runtime to the GatewayUrl output above,"
    echo "and GOVERNANCE_ENABLED=1, to route agent tool calls through governance."
    ;;
  destroy)
    echo "Destroying the governance stack..."
    cdk destroy --force
    ;;
esac
