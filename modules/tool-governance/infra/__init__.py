"""CDK infrastructure for the ADP Tool Governance module.

Ported from the standalone AI-Governance-v2 project, adapted to point at ADP's
Cognito pool and read the module's existing config loader. Every documented
trap/fix from the standalone constructs is preserved verbatim in the comments —
they were established by breaking things against the live AgentCore API.
"""
