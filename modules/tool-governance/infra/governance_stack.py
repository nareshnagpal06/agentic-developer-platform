"""The governed door, the Cedar policy that decides who gets in, the admission
scan in the request path, and the record of what was decided.

Ported from the standalone AI-Governance-v2 GatewayStack, adapted for ADP:
  * Auth points at ADP's Cognito pool (from governance.yaml → config.py).
  * Tenant claim is custom:org_id (ADP's verified claim), carried in config.
  * The dashboard is NOT built here — in ADP it becomes a tab in the existing
    gateway admin UI, not a separate CloudFront app (see design doc).
  * Registry is optional and still NOT in the request path.

This stack creates:
  · a Lambda per tool declared in governance.yaml (demo tools to prove enforcement)
  · a Cedar policy engine, with one policy per tool
  · an AgentCore Gateway with CUSTOM_JWT auth pointed at ADP's Cognito
  · one Gateway target per tool, schema declared inline
  · a Bedrock Guardrails admission scan in the REQUEST path
  · CloudWatch log delivery, so policy decisions are recorded

Authentication (Cognito: is this a real user?) and authorization (Cedar: may THIS
user call THIS tool?) are separate mechanisms. Everyone who logs in gets through
the door; Cedar decides what they find on the other side.

CfnGateway, not the L2 Gateway — the L2 has no policy_engine_configuration.
The authorize IAM actions are granted on Resource "*" — ARN-scoped grants fail
with AccessDenied (verified in the standalone spike).
"""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

from infra.interceptor_construct import AdmissionScan
from infra.observability import GatewayObservability

TOOLS_DIR = Path(__file__).resolve().parent / "tools"


class GovernanceStack(cdk.Stack):
    """The Gateway, its targets, and the Lambdas behind them."""

    def __init__(self, scope: Construct, id: str, *, config, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.config = config

        self.gateway_role = self._create_gateway_role()
        self.tool_functions = {t.name: self._create_tool_lambda(t) for t in config.tools}

        # Built before the Gateway because the Gateway is created holding this
        # Lambda's ARN in interceptor_configurations. Unlike a registry, this IS
        # in the request path — the Gateway calls it on every request, and a
        # refusal here actually refuses.
        self.admission_scan = (
            AdmissionScan(
                self,
                "AdmissionScan",
                config=self.config,
                gateway_role=self.gateway_role,
            )
            if self.config.admission_scan
            else None
        )

        # Order matters and is not arbitrary. The engine must exist before the
        # Gateway can reference its ARN; the policies need the Gateway ARN in
        # their `resource ==` clause. Engine -> Gateway -> policies is the only
        # ordering that avoids a circular dependency.
        self.policy_engine = self._create_policy_engine()
        self.gateway = self._create_gateway()
        self._create_policies()
        self._create_targets()

        # Without this the account has no AgentCore log groups at all and
        # LOG_ONLY mode records nothing observable.
        self.observability = GatewayObservability(
            self,
            "Observability",
            gateway_arn=self.gateway.attr_gateway_arn,
            platform_name=self.config.platform_name,
        )

        self._outputs()

    # ------------------------------------------------------------------ role

    def _create_gateway_role(self) -> iam.Role:
        role = iam.Role(
            self,
            "GatewayRole",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="Execution role for the ADP Tool Governance AgentCore Gateway",
        )
        self._grant_policy_engine_access(role)
        return role

    def _grant_policy_engine_access(self, role: iam.Role) -> None:
        """Grant the authorization actions the Gateway needs at decision time.

        Resource is "*" because ARN-scoped grants do not work today — scoping to
        the policy engine ARN (even with a trailing /*) fails with
        AccessDeniedException. All four actions are granted together because the
        error names only one missing action at a time. Granted now, before the
        engine exists, because the role must hold them when the engine attaches.
        """
        role.add_to_policy(
            iam.PolicyStatement(
                sid="AgentCorePolicyEngineAuthorization",
                actions=[
                    "bedrock-agentcore:AuthorizeAction",
                    "bedrock-agentcore:BatchAuthorizeAction",
                    "bedrock-agentcore:PartiallyAuthorizeActions",
                    "bedrock-agentcore:GetPolicyEngine",
                ],
                resources=["*"],
            )
        )

    # --------------------------------------------------------------- lambdas

    def _create_tool_lambda(self, tool) -> lambda_.Function:
        handler_dir = TOOLS_DIR / tool.handler
        if not handler_dir.is_dir():
            raise FileNotFoundError(
                f"tool {tool.name!r} declares handler {tool.handler!r} but "
                f"{handler_dir} does not exist"
            )

        # An explicit LogGroup, not the deprecated log_retention property (which
        # provisions a custom-resource Lambda per function).
        log_group = logs.LogGroup(
            self,
            f"Tool{_pascal(tool.name)}Logs",
            log_group_name=f"/aws/lambda/{self.config.platform_name}-{tool.name}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        fn = lambda_.Function(
            self,
            f"Tool{_pascal(tool.name)}",
            function_name=f"{self.config.platform_name}-{tool.name}",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="handler.handler",
            code=lambda_.Code.from_asset(str(handler_dir)),
            timeout=cdk.Duration.seconds(30),
            memory_size=256,
            description=f"{tool.name} — governed tool for tenant {tool.tenant}",
            log_group=log_group,
        )
        fn.grant_invoke(iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"))
        fn.grant_invoke(self.gateway_role)
        return fn

    # ---------------------------------------------------------- policy engine

    def _create_policy_engine(self) -> agentcore.CfnPolicyEngine:
        """The thing that answers 'may this caller use this tool?'.

        An engine on its own denies everything: Cedar is default-deny, so the
        absence of a matching permit IS a denial. The policies below are what let
        entitled tenants through.
        """
        return agentcore.CfnPolicyEngine(
            self,
            "PolicyEngine",
            name=self.config.policy_engine_name,
            description=(
                "Cedar authorization for the ADP Tool Governance Gateway. One "
                "policy per tool, keyed on the caller's custom:org_id claim."
            ),
        )

    def _create_policies(self) -> None:
        """One Cedar policy per tool: this tenant (org) may call this tool.

        The syntax is load-bearing and every part was established by experiment.
        Three traps, all of which fail SILENTLY (validate + deploy + enforce
        nothing):

        1. The action name is PREFIXED — "<targetName>___<toolName>" with THREE
           underscores. A wrong name isn't an error; the policy never matches and
           the tool is invisible to everyone.
        2. The tenant claim is reachable ONLY via principal.getTag(). Both
           principal["custom:org_id"] and context[...] pass validation and
           enforce nothing.
        3. Only Gateways are Cedar resources. Tools are ACTIONS, not resources.

        validation_mode=FAIL_ON_ANY_FINDINGS fails the deploy on a malformed
        policy — but it is NOT a safety net: all three wrong syntaxes above pass
        validation. Only a runtime negative control (verify.py) tells the truth.
        """
        gateway_arn = self.gateway.attr_gateway_arn

        for tool in self.config.tools:
            action = f"{tool.name}___{tool.name}"
            claim = self.config.cognito.tenant_claim  # custom:org_id for ADP

            statement = (
                f"permit(\n"
                f"  principal,\n"
                f'  action in [AgentCore::Action::"{action}"],\n'
                f'  resource == AgentCore::Gateway::"{gateway_arn}"\n'
                f") when {{\n"
                f'  principal.hasTag("{claim}") &&\n'
                f'  principal.getTag("{claim}") == "{tool.tenant}"\n'
                f"}};"
            )

            policy = agentcore.CfnPolicy(
                self,
                f"Policy{_pascal(tool.name)}",
                name=f"{tool.tenant}_may_use_{tool.name.replace('-', '_')}",
                policy_engine_id=self.policy_engine.attr_policy_engine_id,
                description=f"Tenant {tool.tenant!r} may call {tool.name!r}",
                definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                    cedar=agentcore.CfnPolicy.CedarPolicyProperty(statement=statement)
                ),
                # ACTIVE = "this policy participates in decisions". NOT the same
                # knob as the Gateway's LOG_ONLY/ENFORCE mode (which decides
                # whether decisions are acted on).
                enforcement_mode="ACTIVE",
                validation_mode="FAIL_ON_ANY_FINDINGS",
            )
            policy.add_resource_dependency(self.policy_engine)
            policy.add_resource_dependency(self.gateway)

    # --------------------------------------------------------------- gateway

    def _create_gateway(self) -> agentcore.CfnGateway:
        """Create the Gateway with CUSTOM_JWT auth against ADP's Cognito.

        CUSTOM_JWT (not IAM auth): an ADP agent holds a Cognito token, not SigV4
        credentials, and IAM auth surfaces no custom:org_id claim for Cedar to
        read.
        """
        cognito = self.config.cognito

        gateway = agentcore.CfnGateway(
            self,
            "Gateway",
            name=f"{self.config.platform_name}-gateway",
            role_arn=self.gateway_role.role_arn,
            protocol_type="MCP",
            authorizer_type="CUSTOM_JWT",
            authorizer_configuration=agentcore.CfnGateway.AuthorizerConfigurationProperty(
                custom_jwt_authorizer=agentcore.CfnGateway.CustomJWTAuthorizerConfigurationProperty(
                    discovery_url=cognito.discovery_url,
                    allowed_audience=[cognito.app_client_id],
                )
            ),
            policy_engine_configuration=agentcore.CfnGateway.GatewayPolicyEngineConfigurationProperty(
                arn=self.policy_engine.attr_policy_engine_arn,
                mode=self.config.enforcement_mode,
            ),
            interceptor_configurations=self._interceptor_configurations(),
            description=(
                "Single governed MCP endpoint. ADP's Cognito authenticates the "
                "caller; Cedar decides which tools they can see and call."
            ),
        )
        if self.admission_scan is not None:
            # The Gateway holds the Lambda's ARN as a token string, so state the
            # ordering rather than relying on CFN inference.
            gateway.node.add_dependency(self.admission_scan.function)

        # IAM eventual-consistency race (observed on first deploy 2026-08-31):
        # the Gateway calls GetPolicyEngine using the gateway role at CREATE
        # time. If the role's inline policy (which grants
        # bedrock-agentcore:GetPolicyEngine + the authorize actions) hasn't
        # finished attaching, the create fails with:
        #   "Access denied while calling GetPolicyEngine ... Confirm this role
        #    has bedrock-agentcore:GetPolicyEngine permissions".
        # CDK renders add_to_policy grants as the role's DefaultPolicy; make the
        # Gateway depend on the whole role node so that policy is attached first.
        gateway.node.add_dependency(self.gateway_role)
        return gateway

    def _interceptor_configurations(self):
        """Attach the admission scan to the Gateway, REQUEST only.

        REQUEST not RESPONSE: the threat is an instruction reaching the model
        before the tool runs, and PROMPT_ATTACK is not evaluated on
        source=OUTPUT anyway.

        pass_request_headers=False: the headers carry the caller's bearer token,
        which this Lambda has no need of (identity is Cedar's job). If a future
        version needs the tenant claim, take it from the request context.
        """
        if self.admission_scan is None:
            return None

        return [
            agentcore.CfnGateway.GatewayInterceptorConfigurationProperty(
                interception_points=["REQUEST"],
                interceptor=agentcore.CfnGateway.InterceptorConfigurationProperty(
                    lambda_=agentcore.CfnGateway.LambdaInterceptorConfigurationProperty(
                        arn=self.admission_scan.function.function_arn
                    )
                ),
                input_configuration=agentcore.CfnGateway.InterceptorInputConfigurationProperty(
                    pass_request_headers=False
                ),
            )
        ]

    def _create_targets(self) -> None:
        """One target per tool, schema declared inline.

        Target name matters: Cedar addresses a tool as
        AgentCore::Action::"<targetName>___<toolName>" (triple underscore). Using
        the tool name for both keeps the generated policies readable.
        """
        for tool in self.config.tools:
            fn = self.tool_functions[tool.name]

            target = agentcore.CfnGatewayTarget(
                self,
                f"Target{_pascal(tool.name)}",
                gateway_identifier=self.gateway.attr_gateway_identifier,
                name=tool.name,
                description=tool.description,
                target_configuration=agentcore.CfnGatewayTarget.TargetConfigurationProperty(
                    mcp=agentcore.CfnGatewayTarget.McpTargetConfigurationProperty(
                        lambda_=agentcore.CfnGatewayTarget.McpLambdaTargetConfigurationProperty(
                            lambda_arn=fn.function_arn,
                            tool_schema=agentcore.CfnGatewayTarget.ToolSchemaProperty(
                                inline_payload=[_tool_schema(tool)]
                            ),
                        )
                    )
                ),
                credential_provider_configurations=[
                    # Outbound identity: the target is called with the Gateway's
                    # own role. OAUTH (per-user tokens) is the intended next step
                    # and is a change to this block, not a redesign.
                    agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
                        credential_provider_type="GATEWAY_IAM_ROLE"
                    )
                ],
            )
            target.add_resource_dependency(self.gateway)

    # --------------------------------------------------------------- outputs

    def _outputs(self) -> None:
        cdk.CfnOutput(
            self,
            "GatewayUrl",
            value=self.gateway.attr_gateway_url,
            description="The single MCP endpoint. Set this as GOVERNANCE_MCP_URL on the agent runtime.",
        )
        cdk.CfnOutput(self, "GatewayId", value=self.gateway.attr_gateway_identifier)
        cdk.CfnOutput(self, "GatewayArn", value=self.gateway.attr_gateway_arn)
        cdk.CfnOutput(
            self,
            "EnforcementMode",
            value=self.config.enforcement_mode,
            description="LOG_ONLY records decisions; ENFORCE acts on them",
        )
        cdk.CfnOutput(
            self,
            "PolicyEngineArn",
            value=self.policy_engine.attr_policy_engine_arn,
            description="Cedar policy engine attached to the Gateway",
        )
        cdk.CfnOutput(
            self,
            "DecisionLogGroup",
            value=self.observability.log_group.log_group_name,
            description="Where every ALLOW and DENY is recorded",
        )
        if self.admission_scan is not None:
            cdk.CfnOutput(
                self,
                "AdmissionScanMode",
                value=self.config.admission_scan.mode,
                description="OBSERVE scans and logs; ENFORCE refuses the call",
            )
            cdk.CfnOutput(
                self,
                "GuardrailId",
                value=self.admission_scan.guardrail_id,
                description="Bedrock guardrail consulted on every request",
            )
        cdk.CfnOutput(
            self,
            "CognitoDiscoveryUrl",
            value=self.config.cognito.discovery_url,
            description="OIDC discovery endpoint the Gateway validates tokens against",
        )


def _tool_schema(tool) -> "agentcore.CfnGatewayTarget.ToolDefinitionProperty":
    """Build the MCP tool definition the Gateway advertises in tools/list."""
    properties = {
        arg.name: agentcore.CfnGatewayTarget.SchemaDefinitionProperty(
            type=arg.type,
            description=arg.description,
        )
        for arg in tool.arguments
    }
    return agentcore.CfnGatewayTarget.ToolDefinitionProperty(
        name=tool.name,
        description=tool.description,
        input_schema=agentcore.CfnGatewayTarget.SchemaDefinitionProperty(
            type="object",
            properties=properties,
            required=[a.name for a in tool.arguments if a.required],
        ),
    )


def _pascal(value: str) -> str:
    """finance-reports -> FinanceReports, for CDK logical IDs."""
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
