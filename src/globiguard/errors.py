from __future__ import annotations

from typing import Any


class GlobiguardConfigError(ValueError):
    """Raised when SDK configuration is invalid before an HTTP request is sent."""


class GlobiguardHttpError(RuntimeError):
    """Raised when a GlobiGuard service returns a non-success status code."""

    def __init__(self, message: str, status: int, body: Any) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class GlobiguardAuthorityError(RuntimeError):
    """Raised when GlobiGuard blocks, queues, or cannot safely authorize an action."""

    def __init__(
        self,
        *,
        kind: str,
        message: str,
        authorization_id: str | None = None,
        queue_entry_id: str | None = None,
        evidence_package_id: str | None = None,
        retry_after_seconds: int | None = None,
        safe_details: dict[str, str | int | float | bool | None] | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.authorization_id = authorization_id
        self.queue_entry_id = queue_entry_id
        self.evidence_package_id = evidence_package_id
        self.retry_after_seconds = retry_after_seconds
        self.safe_details = safe_details

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": str(self),
            "authorizationId": self.authorization_id,
            "queueEntryId": self.queue_entry_id,
            "evidencePackageId": self.evidence_package_id,
            "retryAfterSeconds": self.retry_after_seconds,
            "safeDetails": self.safe_details,
        }
