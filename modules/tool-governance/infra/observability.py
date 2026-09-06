"""Make the Gateway's policy decisions visible (CloudWatch vended-logs delivery).

Ported unchanged from the standalone AI-Governance-v2 project — this is pure
AgentCore/CloudWatch behaviour, nothing ADP-specific.

Without this, there is no record of anything. AgentCore creates no log groups of
its own: an account with a busy, fully-enforcing Gateway has zero log groups
until someone wires up CloudWatch Logs *delivery* (the "vended logs" mechanism —
a delivery source, a delivery destination, and a delivery joining them).

That matters more than it sounds, because LOG_ONLY mode is worthless without it.
The whole point of LOG_ONLY is to answer "what would this policy have blocked?"
before it can break anyone's day — and if nothing is being delivered, the answer
is silently "we have no idea".

Verified by experiment (standalone project, 2026-08-05):
  · Log types the Gateway accepts: TRACES, APPLICATION_LOGS, USAGE_LOGS.
    Policy decisions arrive in APPLICATION_LOGS. There is no POLICY_DECISIONS or
    AUDIT_LOGS type — those names are rejected outright.
  · The policy engine is NOT a valid delivery source; only the Gateway is.
  · TRACES to a log group is rejected (traces want X-Ray). USAGE_LOGS is not
    supported for gateways. Hence APPLICATION_LOGS only.
  · Delivery takes ~30-60s to begin flowing. An empty log group on first look is
    not a misconfiguration.

Two limits worth knowing:
  · tools/list produces NO policy record — but it IS enforced (Cedar filters the
    listing). The log answers "who called what", not "who could see what".
  · The principal is a Cognito `sub` UUID, not an email and not the tenant.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import aws_logs as logs
from constructs import Construct

# The only log type that carries policy decisions. POLICY_DECISIONS and
# AUDIT_LOGS do not exist; TRACES/USAGE_LOGS cannot be delivered to a log group
# from a Gateway.
LOG_TYPE = "APPLICATION_LOGS"


class GatewayObservability(Construct):
    """Deliver the Gateway's application logs — including policy decisions.

    Ordering is enforced with explicit dependencies rather than left to
    CloudFormation. The delivery references both source and destination *by name
    and ARN* (strings, not object references), so CloudFormation cannot infer the
    dependency and will happily try to create the join first.
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        gateway_arn: str,
        platform_name: str,
        retention_days: logs.RetentionDays = logs.RetentionDays.ONE_MONTH,
    ) -> None:
        super().__init__(scope, id)

        # The /aws/vendedlogs/ prefix is a convention with teeth: CloudWatch
        # grants delivery services write access to it without a resource policy.
        self.log_group = logs.LogGroup(
            self,
            "PolicyDecisionLogs",
            log_group_name=f"/aws/vendedlogs/bedrock-agentcore/{platform_name}/{LOG_TYPE}",
            retention=retention_days,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        source = logs.CfnDeliverySource(
            self,
            "Source",
            name=f"{platform_name}-gateway-{LOG_TYPE.lower()}",
            log_type=LOG_TYPE,
            resource_arn=gateway_arn,
        )

        destination = logs.CfnDeliveryDestination(
            self,
            "Destination",
            name=f"{platform_name}-gateway-{LOG_TYPE.lower()}-dest",
            destination_resource_arn=self.log_group.log_group_arn,
        )

        delivery = logs.CfnDelivery(
            self,
            "Delivery",
            delivery_source_name=source.name,
            delivery_destination_arn=destination.attr_arn,
        )
        delivery.add_resource_dependency(source)
        delivery.add_resource_dependency(destination)
