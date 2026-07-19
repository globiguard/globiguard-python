from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from .errors import GlobiguardAuthorityError, GlobiguardConfigError
from .resources import ActionsClient, AuditClient, QueueClient


def derive_action_idempotency_key(
    *,
    stable_seed: str,
    action_type: str,
    actor_id: str | None = None,
    payload_sha256: str | None = None,
    window_bucket: str | None = None,
) -> str:
    _assert_non_empty("stable_seed", stable_seed)
    _assert_non_empty("action_type", action_type)
    payload = json.dumps(
        {
            "stableSeed": stable_seed,
            "actionType": action_type,
            "actorId": actor_id,
            "payloadSha256": payload_sha256,
            "windowBucket": window_bucket,
        },
        separators=(",", ":"),
    )
    return f"gg_idem_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:48]}"


def generate_correlation_id() -> str:
    return secrets.token_hex(16)


class GovernedActionsClient:
    def __init__(
        self,
        *,
        actions: ActionsClient,
        audit: AuditClient,
        queue: QueueClient,
    ) -> None:
        self._actions = actions
        self._audit = audit
        self._queue = queue

    def authorize_action(self, request: dict[str, Any]) -> Any:
        return self._actions.authorize(request)

    def authorize_action_or_throw(self, request: dict[str, Any]) -> Any:
        decision = self._actions.authorize(request)
        return _require_executable_decision(decision)

    def request_approval(self, request: dict[str, Any]) -> Any:
        return self._actions.create_approval(request)

    def get_approval_status(self, approval_id: str) -> Any:
        return self._actions.get_approval(approval_id)

    def get_evidence_references(self, **request: str | None) -> Any:
        return self._actions.list_evidence(**request)

    def export_evidence_package(self, request: dict[str, Any] | None = None) -> Any:
        return self._audit.export(request)

    def get_evidence_package_summary(self, evidence_package_id: str) -> Any:
        return self._audit.get_evidence_package_summary(evidence_package_id)

    def get_incident_replay(self, **request: str | None) -> Any:
        return self._audit.get_incident_replay(**request)

    def wait_for_approval(
        self,
        *,
        queue_entry_id: str,
        max_attempts: int = 60,
        interval_seconds: float = 1.0,
    ) -> Any:
        if max_attempts < 1:
            raise GlobiguardConfigError("max_attempts must be at least 1.")

        for attempt in range(1, max_attempts + 1):
            entry = self._queue.get(queue_entry_id)
            status = entry.get("status")
            if status in {"APPROVED", "AUTO_APPROVED", "RESUMED"}:
                return entry
            if status in {"REJECTED", "EXPIRED", "FAILED"}:
                raise GlobiguardAuthorityError(
                    kind="POLICY_BLOCKED",
                    message=(
                        f"Queued action resolved as {status}; do not perform the "
                        "downstream business action."
                    ),
                    queue_entry_id=entry.get("id"),
                    safe_details={"status": status},
                )
            if status == "MODIFIED":
                raise GlobiguardAuthorityError(
                    kind="STEP_UP_REQUIRED",
                    message=(
                        "The reviewer approved a modified action summary. Rebuild "
                        "the real payload from the authoritative review result and "
                        "request a new authorization before executing it."
                    ),
                    queue_entry_id=entry.get("id"),
                    safe_details={"status": status},
                )
            if status not in {"PENDING", "ESCALATED"}:
                raise GlobiguardAuthorityError(
                    kind="CONTROL_PLANE_UNAVAILABLE",
                    message=(
                        "GlobiGuard returned an unsupported approval state; the "
                        "downstream business action remains stopped."
                    ),
                    queue_entry_id=entry.get("id"),
                    safe_details={"status": status},
                )
            if attempt < max_attempts:
                time.sleep(interval_seconds)

        raise GlobiguardAuthorityError(
            kind="QUEUED_FOR_REVIEW",
            message=(
                "Queued action is still pending after the configured wait attempts; "
                "do not perform the downstream business action yet."
            ),
            queue_entry_id=queue_entry_id,
        )


def _require_executable_decision(decision: Any) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise GlobiguardAuthorityError(
            kind="CONTROL_PLANE_UNAVAILABLE",
            message=(
                "GlobiGuard returned an invalid decision response; do not perform "
                "the downstream business action."
            ),
        )
    decision_name = decision.get("decision")
    if decision_name in {"ALLOW", "MODIFY"}:
        return decision
    if decision_name == "BLOCK":
        raise GlobiguardAuthorityError(
            kind="POLICY_BLOCKED",
            message="GlobiGuard blocked the governed action.",
            authorization_id=decision.get("authorizationId"),
            queue_entry_id=decision.get("queueEntryId"),
            safe_details={
                "decision": decision_name,
                "reason": decision.get("reason"),
            },
        )
    if decision_name == "QUEUE":
        raise GlobiguardAuthorityError(
            kind="QUEUED_FOR_REVIEW",
            message=(
                "GlobiGuard queued the governed action for review; do not "
                "perform the downstream business action yet."
            ),
            authorization_id=decision.get("authorizationId"),
            queue_entry_id=decision.get("queueEntryId"),
            safe_details={
                "decision": decision_name,
                "approvalState": decision.get("approvalState"),
            },
        )
    raise GlobiguardAuthorityError(
        kind="CONTROL_PLANE_UNAVAILABLE",
        message=(
            "GlobiGuard returned an unsupported decision; do not perform the "
            "downstream business action."
        ),
        authorization_id=decision.get("authorizationId"),
        queue_entry_id=decision.get("queueEntryId"),
        safe_details={"decision": decision_name},
    )


def _assert_non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise GlobiguardConfigError(f"{name} must be a non-empty string.")
