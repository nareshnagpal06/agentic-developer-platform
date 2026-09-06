"""The admission scan — a Bedrock Guardrail + the interceptor Lambda the Gateway
invokes on every request. In the request path; can refuse.

Ported from the standalone AI-Governance-v2 project. The Lambda code is the
module's already-ported handler at ../interceptor/handler.py — this construct
just packages and wires it.

WHY PROMPT_ATTACK AT HIGH (from the standalone project's measurements)
Tested against six payloads: PROMPT_ATTACK catches a politely-worded injection
that a keyword/topic guardrail misses, and does NOT falsely block a legitimate
admin-tool description (which the old five-filter guardrail did). One precise
filter beats five loose ones. HIGH, because the politely-phrased injection is
only caught at that strength and HIGH produced no false positives on real tool
descriptions.

WHAT THIS SCAN CANNOT DO
A quiet, documentation-shaped exfiltration sentence passes the scan. It raises
the cost of the obvious attack; it does not solve semantic trust in third-party
tool text. The human review of tool descriptions is the control for that.

SERVICE BEHAVIOUR
PROMPT_ATTACK is evaluated on source=INPUT only — a response-side scan using this
filter reports clean forever. output_strength must be set and is NONE.

GRANTS
Both grants are required. The Gateway invokes its interceptor as its own
EXECUTION ROLE, not as the bedrock-agentcore service principal — granting only
the service principal produces "Access denied while invoking Lambda function" and
every request fails with HTTP 500, with the Gateway staying READY and the
interceptor's log group staying empty (nothing to debug in the obvious place).
So BOTH the gateway role and the service principal get invoke.
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

# The interceptor Lambda code lives in the module's interceptor/ package
# (handler.py was ported there already).
INTERCEPTOR_CODE_DIR = Path(__file__).resolve().parent.parent / "interceptor"

# HIGH, not MEDIUM. See module docstring — the politely-phrased injection is only
# caught at HIGH, and HIGH produced no false positives on real tool descriptions.
PROMPT_ATTACK_STRENGTH = "HIGH"


class AdmissionScan(Construct):
    """A Bedrock guardrail and the Lambda the Gateway calls to consult it.

    Does NOT attach itself to the Gateway. The Gateway is created with
    interceptor_configurations pointing at this Lambda, which means the Lambda
    must exist first — so the wiring lives in the stack, in dependency order, and
    this construct only builds the pieces.
    """

    def __init__(
        self, scope: Construct, id: str, *, config, gateway_role: iam.IRole
    ) -> None:
        super().__init__(scope, id)

        if config.admission_scan is None:
            raise ValueError(
                "AdmissionScan requires an admission_scan section in governance.yaml"
            )

        self.config = config
        self.scan_config = config.admission_scan

        self.guardrail = self._create_guardrail()
        self.function = self._create_function()

        # The Gateway invokes its interceptor as its OWN execution role — grant it.
        self.function.grant_invoke(gateway_role)

    # ------------------------------------------------------------- guardrail

    def _create_guardrail(self) -> bedrock.CfnGuardrail:
        """One filter, doing one job: PROMPT_ATTACK on input.

        Deliberately not the standalone's original five content filters. HATE,
        SEXUAL, INSULTS are about harmful *content*; the threat here is an
        *instruction* hidden in text fed to a model. PROMPT_ATTACK is the filter
        built for this threat.
        """
        return bedrock.CfnGuardrail(
            self,
            "Guardrail",
            name=f"{self.config.platform_name}-admission-scan",
            description=(
                "Prompt-injection scan for the ADP Tool Governance Gateway. "
                "Applied to tool arguments on every call by the request interceptor."
            ),
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK",
                        input_strength=PROMPT_ATTACK_STRENGTH,
                        # NONE, and required. PROMPT_ATTACK is not evaluated on
                        # source=OUTPUT — any other value would imply a
                        # response-side protection that does not exist.
                        output_strength="NONE",
                    )
                ]
            ),
            blocked_input_messaging=(
                "Blocked by the ADP governance admission scan: this content was "
                "flagged as a possible prompt-injection attempt."
            ),
            blocked_outputs_messaging="Blocked by the ADP governance admission scan.",
        )

    @property
    def guardrail_id(self) -> str:
        return self.guardrail.attr_guardrail_id

    # -------------------------------------------------------------- function

    def _create_function(self) -> lambda_.Function:
        """The interceptor itself.

        Timeout is 10s against a measured Guardrails latency of ~106-128ms — a
        wide backstop margin, not a budget. The handler's own boto3 read timeout
        (5s) does the real limiting: a boto3 timeout produces a fail-closed
        verdict that gets logged, whereas a Lambda timeout produces no verdict.
        """
        log_group = logs.LogGroup(
            self,
            "Logs",
            log_group_name=f"/aws/lambda/{self.config.platform_name}-admission-scan",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        fn = lambda_.Function(
            self,
            "Function",
            function_name=f"{self.config.platform_name}-admission-scan",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="handler.handler",
            code=lambda_.Code.from_asset(str(INTERCEPTOR_CODE_DIR)),
            timeout=cdk.Duration.seconds(10),
            memory_size=512,
            description=(
                "Gateway request interceptor — scans tool arguments for prompt "
                "injection via Bedrock Guardrails"
            ),
            log_group=log_group,
            environment={
                "GUARDRAIL_ID": self.guardrail_id,
                "GUARDRAIL_VERSION": "DRAFT",
                "INTERCEPTOR_MODE": self.scan_config.mode,
                "FAIL_OPEN": str(self.scan_config.fail_open).lower(),
            },
        )

        fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"],
                resources=[self.guardrail.attr_guardrail_arn],
            )
        )

        # The Gateway invokes this as the service principal too — grant it, or
        # the interceptor silently never runs (which, being allow-by-absence,
        # looks exactly like a scan that passes everything).
        fn.grant_invoke(iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"))

        return fn
