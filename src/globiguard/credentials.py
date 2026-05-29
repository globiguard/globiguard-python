from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .errors import GlobiguardConfigError

Environment = Literal["local", "sandbox", "live"]
CredentialKind = Literal["publishable", "secret", "local"]


def _require_non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise GlobiguardConfigError(f"{name} must be a non-empty string.")


@dataclass(frozen=True)
class PublishableCredential:
    project_id: str
    token: str
    kind: CredentialKind = "publishable"

    def __post_init__(self) -> None:
        _require_non_empty("project_id", self.project_id)
        _require_non_empty("token", self.token)

    def __repr__(self) -> str:
        return "PublishableCredential(project_id={!r}, token=<redacted>)".format(
            self.project_id
        )


@dataclass(frozen=True)
class SecretCredential:
    project_id: str
    token: str
    environment: Literal["sandbox", "live"]
    kind: CredentialKind = "secret"

    def __post_init__(self) -> None:
        _require_non_empty("project_id", self.project_id)
        _require_non_empty("token", self.token)
        if self.environment == "local":
            raise GlobiguardConfigError("Secret credentials cannot target local.")

    def __repr__(self) -> str:
        return (
            "SecretCredential(project_id={!r}, token=<redacted>, environment={!r})"
        ).format(self.project_id, self.environment)


@dataclass(frozen=True)
class LocalCredential:
    project_id: str | None = None
    token: str | None = None
    kind: CredentialKind = "local"

    def __repr__(self) -> str:
        project = repr(self.project_id) if self.project_id else "None"
        token = "<redacted>" if self.token else "None"
        return f"LocalCredential(project_id={project}, token={token})"


Credential = PublishableCredential | SecretCredential | LocalCredential
