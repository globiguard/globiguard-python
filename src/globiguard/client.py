from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .brain import BrainClient
from .credentials import Credential, Environment, LocalCredential, SecretCredential
from .errors import GlobiguardConfigError
from .governed_actions import GovernedActionsClient
from .observability import ObservabilityClient
from .resources import (
    ActionsClient,
    AuditClient,
    InstallsClient,
    OrgsClient,
    PoliciesClient,
    QueueClient,
    WorkflowsClient,
)
from .transport import Transport, TransportCallable, assert_service_url

ActionGatewayMode = Literal["control_plane", "sidecar", "gateway"]


@dataclass(frozen=True)
class ActionGatewayConfig:
    mode: ActionGatewayMode = "control_plane"


@dataclass(frozen=True)
class ServerClient:
    kind: Literal["server"]
    environment: Environment
    action_gateway: ActionGatewayConfig
    control_plane: Transport
    actions: ActionsClient
    audit: AuditClient
    installs: InstallsClient
    orgs: OrgsClient
    policies: PoliciesClient
    queue: QueueClient
    workflows: WorkflowsClient
    governed_actions: GovernedActionsClient
    observe: ObservabilityClient
    brain: BrainClient | None = None
    gateway: Transport | None = None
    sidecar: Transport | None = None


@dataclass(frozen=True)
class BrowserClient:
    kind: Literal["browser"]
    environment: Environment
    actions: ActionsClient
    audit: AuditClient
    installs: InstallsClient
    policies: PoliciesClient
    queue: QueueClient
    workflows: WorkflowsClient


def create_server_client(
    *,
    environment: Environment,
    services: dict[str, str],
    credential: Credential,
    action_gateway: ActionGatewayConfig | None = None,
    client_name: str = "globiguard-python",
    timeout: float = 10.0,
    opener: TransportCallable | None = None,
) -> ServerClient:
    _validate_timeout(timeout)
    _require_service(services, "controlPlane")
    _assert_server_credential(credential, environment)

    require_local = isinstance(credential, LocalCredential)
    for service_name in ("controlPlane", "brain", "gateway", "sidecar"):
        if services.get(service_name):
            assert_service_url(
                service_name,
                services[service_name],
                environment,
                require_local_host=require_local,
            )

    control_plane = _transport(
        services["controlPlane"],
        client_name,
        credential,
        environment,
        timeout,
        opener,
    )
    brain_transport = _optional_transport(
        services.get("brain"), client_name, credential, environment, timeout, opener
    )
    gateway = _optional_transport(
        services.get("gateway"), client_name, credential, environment, timeout, opener
    )
    sidecar = _optional_transport(
        services.get("sidecar"), client_name, credential, environment, timeout, opener
    )

    gateway_config = action_gateway or ActionGatewayConfig()
    action_transport = _resolve_action_transport(
        gateway_config, control_plane=control_plane, gateway=gateway, sidecar=sidecar
    )
    actions = ActionsClient(action_transport)
    audit = AuditClient(control_plane)
    queue = QueueClient(control_plane)
    brain = BrainClient(brain_transport) if brain_transport is not None else None

    return ServerClient(
        kind="server",
        environment=environment,
        action_gateway=gateway_config,
        control_plane=control_plane,
        brain=brain,
        gateway=gateway,
        sidecar=sidecar,
        actions=actions,
        audit=audit,
        installs=InstallsClient(control_plane),
        orgs=OrgsClient(control_plane),
        policies=PoliciesClient(control_plane),
        queue=queue,
        workflows=WorkflowsClient(control_plane),
        governed_actions=GovernedActionsClient(
            actions=actions,
            audit=audit,
            queue=queue,
            brain=brain,
        ),
        observe=ObservabilityClient(control_plane),
    )


def create_browser_client(
    *,
    environment: Environment,
    services: dict[str, str],
    credential: Credential,
    client_name: str = "globiguard-python",
    timeout: float = 10.0,
    opener: TransportCallable | None = None,
) -> BrowserClient:
    _validate_timeout(timeout)
    _require_service(services, "controlPlane")
    _assert_browser_credential(credential, environment)
    assert_service_url(
        "controlPlane",
        services["controlPlane"],
        environment,
        require_local_host=isinstance(credential, LocalCredential),
    )
    control_plane = _transport(
        services["controlPlane"],
        client_name,
        credential,
        environment,
        timeout,
        opener,
    )
    return BrowserClient(
        kind="browser",
        environment=environment,
        actions=ActionsClient(control_plane, read_only=True),
        audit=AuditClient(control_plane, read_only=True),
        installs=InstallsClient(control_plane),
        policies=PoliciesClient(control_plane, read_only=True),
        queue=QueueClient(control_plane, read_only=True),
        workflows=WorkflowsClient(control_plane, read_only=True),
    )


def _transport(
    base_url: str,
    client_name: str,
    credential: Credential,
    environment: Environment,
    timeout: float,
    opener: TransportCallable | None,
) -> Transport:
    return Transport(
        base_url=base_url,
        client_name=client_name,
        credential=credential,
        environment=environment,
        timeout=timeout,
        opener=opener,
    )


def _optional_transport(
    base_url: str | None,
    client_name: str,
    credential: Credential,
    environment: Environment,
    timeout: float,
    opener: TransportCallable | None,
) -> Transport | None:
    if not base_url:
        return None
    return _transport(base_url, client_name, credential, environment, timeout, opener)


def _resolve_action_transport(
    action_gateway: ActionGatewayConfig,
    *,
    control_plane: Transport,
    gateway: Transport | None,
    sidecar: Transport | None,
) -> Transport:
    if action_gateway.mode == "control_plane":
        return control_plane
    if action_gateway.mode == "gateway":
        if not gateway:
            raise GlobiguardConfigError("Action gateway mode 'gateway' requires services.gateway.")
        return gateway
    if action_gateway.mode == "sidecar":
        if not sidecar:
            raise GlobiguardConfigError("Action gateway mode 'sidecar' requires services.sidecar.")
        return sidecar
    raise GlobiguardConfigError(
        "Action gateway mode must be control_plane, sidecar, or gateway."
    )


def _require_service(services: dict[str, str], name: str) -> None:
    if not services.get(name):
        raise GlobiguardConfigError(f"{name} service URL is required.")


def _assert_server_credential(credential: Credential, environment: Environment) -> None:
    if credential.kind == "publishable":
        raise GlobiguardConfigError("Server clients require secret or local credentials.")
    if credential.kind not in {"secret", "local"}:
        raise GlobiguardConfigError(
            "Server clients require a recognized secret or local credential kind."
        )
    if isinstance(credential, LocalCredential) and environment != "local":
        raise GlobiguardConfigError("Local credentials may only be used with the local environment.")
    if isinstance(credential, SecretCredential) and credential.environment != environment:
        raise GlobiguardConfigError(
            "Secret credential environment must match the client environment."
        )


def _assert_browser_credential(credential: Credential, environment: Environment) -> None:
    if credential.kind == "secret":
        raise GlobiguardConfigError("Browser clients require publishable or local credentials.")
    if credential.kind not in {"publishable", "local"}:
        raise GlobiguardConfigError(
            "Browser clients require a recognized publishable or local credential kind."
        )
    if isinstance(credential, LocalCredential) and environment != "local":
        raise GlobiguardConfigError("Local credentials may only be used with the local environment.")


def _validate_timeout(timeout: float) -> None:
    if timeout <= 0:
        raise GlobiguardConfigError("timeout must be greater than zero.")
