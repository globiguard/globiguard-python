from __future__ import annotations

from typing import Any, Literal, TypedDict

from .credentials import Environment
from .errors import GlobiguardConfigError

DeploymentMode = Literal["hosted", "self_hosted", "sovereign"]
InstallIssuerMode = Literal["globiguard_issued", "customer_issued"]
InstallReportingMode = Literal["default", "opt_in", "disabled"]

GLOBIGUARD_DEPLOYMENT_MODES = ("hosted", "self_hosted", "sovereign")
GLOBIGUARD_INSTALL_ISSUER_MODES = ("globiguard_issued", "customer_issued")
GLOBIGUARD_INSTALL_REPORTING_MODES = ("default", "opt_in", "disabled")


class BootstrapProfile(TypedDict, total=False):
    environment: Environment
    deploymentMode: DeploymentMode
    issuerMode: InstallIssuerMode
    installReporting: InstallReportingMode
    installLabel: str
    installFingerprint: str


def resolve_bootstrap_profile(profile: BootstrapProfile) -> dict[str, Any]:
    _assert_allowed(profile.get("environment"), ("local", "sandbox", "live"), "environment")
    _assert_allowed(profile.get("deploymentMode"), GLOBIGUARD_DEPLOYMENT_MODES, "deploymentMode")
    _assert_allowed(profile.get("issuerMode"), GLOBIGUARD_INSTALL_ISSUER_MODES, "issuerMode")
    _assert_allowed(
        profile.get("installReporting"),
        GLOBIGUARD_INSTALL_REPORTING_MODES,
        "installReporting",
    )

    deployment_mode = profile["deploymentMode"]
    issuer_mode = profile["issuerMode"]
    install_reporting = profile["installReporting"]

    if deployment_mode == "hosted" and issuer_mode != "globiguard_issued":
        raise GlobiguardConfigError(
            "Hosted deployments must use globiguard-issued bootstrap credentials."
        )
    if deployment_mode != "hosted" and issuer_mode != "customer_issued":
        raise GlobiguardConfigError(
            "Self-hosted and sovereign deployments must use customer-issued bootstrap credentials."
        )
    if deployment_mode != "hosted" and install_reporting == "default":
        raise GlobiguardConfigError(
            "Self-hosted and sovereign deployments must set installReporting to opt_in or disabled explicitly."
        )

    return {
        **profile,
        "installRegistrationAllowed": install_reporting != "disabled",
    }


def build_install_registration_request(
    profile: BootstrapProfile,
    *,
    package_name: str,
    package_version: str,
    integration_kind: str,
    runtime_kind: str,
    metadata: dict[str, str | int | float | bool] | None = None,
) -> dict[str, Any]:
    resolved = resolve_bootstrap_profile(profile)
    _assert_install_registration_allowed(resolved)
    return {
        "packageName": package_name,
        "packageVersion": package_version,
        "integrationKind": integration_kind,
        "runtimeKind": runtime_kind,
        "environment": resolved["environment"],
        "deploymentMode": resolved["deploymentMode"],
        "issuerMode": resolved["issuerMode"],
        "installReporting": resolved["installReporting"],
        "installLabel": resolved.get("installLabel"),
        "installFingerprint": resolved.get("installFingerprint"),
        "metadata": metadata,
    }


def build_install_heartbeat_request(
    profile: BootstrapProfile,
    *,
    package_version: str,
    runtime_kind: str,
    metadata: dict[str, str | int | float | bool] | None = None,
) -> dict[str, Any]:
    resolved = resolve_bootstrap_profile(profile)
    _assert_install_registration_allowed(resolved)
    return {
        "packageVersion": package_version,
        "runtimeKind": runtime_kind,
        "environment": resolved["environment"],
        "deploymentMode": resolved["deploymentMode"],
        "issuerMode": resolved["issuerMode"],
        "installReporting": resolved["installReporting"],
        "installLabel": resolved.get("installLabel"),
        "installFingerprint": resolved.get("installFingerprint"),
        "metadata": metadata,
    }


def _assert_allowed(value: object, allowed_values: tuple[str, ...], field_name: str) -> None:
    if value not in allowed_values:
        raise GlobiguardConfigError(f"{field_name} must be one of: {', '.join(allowed_values)}.")


def _assert_install_registration_allowed(profile: dict[str, Any]) -> None:
    if not profile["installRegistrationAllowed"]:
        raise GlobiguardConfigError(
            "Install registration and heartbeat are disabled for this bootstrap profile."
        )
