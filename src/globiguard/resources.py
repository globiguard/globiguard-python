from __future__ import annotations

from typing import Any

from .errors import GlobiguardConfigError
from .transport import Transport, encode_path_segment


class ActionsClient:
    def __init__(self, transport: Transport, *, read_only: bool = False) -> None:
        self._transport = transport
        self._read_only = read_only

    def get_authorization(self, authorization_id: str) -> Any:
        return self._transport.request(
            f"/v1/actions/authorizations/{encode_path_segment(authorization_id)}"
        )

    def get_approval(self, approval_id: str) -> Any:
        return self._transport.request(
            f"/v1/actions/approvals/{encode_path_segment(approval_id)}"
        )

    def list_evidence(
        self,
        *,
        authorization_id: str | None = None,
        approval_id: str | None = None,
        workflow_run_id: str | None = None,
    ) -> Any:
        return self._transport.request(
            "/v1/actions/evidence",
            query={
                "authorizationId": authorization_id,
                "approvalId": approval_id,
                "workflowRunId": workflow_run_id,
            },
        )

    def get_evidence(self, evidence_ref_id: str) -> Any:
        return self._transport.request(
            f"/v1/actions/evidence/{encode_path_segment(evidence_ref_id)}"
        )

    def authorize(self, request: dict[str, Any]) -> Any:
        self._require_write("authorize")
        return self._transport.request(
            "/v1/actions/authorize", method="POST", body=request
        )

    def create_approval(self, request: dict[str, Any]) -> Any:
        self._require_write("create_approval")
        return self._transport.request(
            "/v1/actions/approvals", method="POST", body=request
        )

    def _require_write(self, method: str) -> None:
        if self._read_only:
            raise GlobiguardConfigError(f"{method} requires a server client.")


class AuditClient:
    def __init__(self, transport: Transport, *, read_only: bool = False) -> None:
        self._transport = transport
        self._read_only = read_only

    def list(
        self,
        *,
        from_: str | None = None,
        to: str | None = None,
        decision: str | None = None,
        workflow_run_id: str | None = None,
        page: int | None = None,
        limit: int | None = None,
    ) -> Any:
        return self._transport.request(
            "/v1/audit",
            query={
                "from": from_,
                "to": to,
                "decision": decision,
                "workflow": workflow_run_id,
                "page": page,
                "limit": limit,
            },
        )

    def get(self, audit_event_id: str) -> Any:
        return self._transport.request(f"/v1/audit/{encode_path_segment(audit_event_id)}")

    def export(self, request: dict[str, Any] | None = None) -> Any:
        if self._read_only:
            raise GlobiguardConfigError("export requires a server client.")
        response = self._transport.request(
            "/v1/audit/export", method="POST", body=request or {}
        )
        if not isinstance(response, dict):
            return response
        return {
            "status": response.get("status"),
            "artifactExportId": response.get("artifact_export_id"),
            "evidencePackageId": response.get("evidence_package_id"),
            "format": response.get("format"),
            "checksum": response.get("checksum"),
            "artifactJson": response.get("artifact_json"),
            "artifact": response.get("artifact"),
        }

    def get_evidence_package_summary(self, evidence_package_id: str) -> Any:
        encoded = encode_path_segment(evidence_package_id)
        return self._transport.request(f"/v1/audit/evidence-packages/{encoded}/summary")

    def get_incident_replay(
        self,
        *,
        workflow_run_id: str | None = None,
        correlation_id: str | None = None,
        queue_entry_id: str | None = None,
        audit_event_id: str | None = None,
        authorization_id: str | None = None,
    ) -> Any:
        return self._transport.request(
            "/v1/audit/incident-replay",
            query={
                "workflowRunId": workflow_run_id,
                "correlationId": correlation_id,
                "queueEntryId": queue_entry_id,
                "auditEventId": audit_event_id,
                "authorizationId": authorization_id,
            },
        )


class InstallsClient:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def register(self, request: dict[str, Any]) -> Any:
        return self._transport.request("/v1/installs", method="POST", body=request)

    def heartbeat(self, install_id: str, request: dict[str, Any]) -> Any:
        encoded = encode_path_segment(install_id)
        return self._transport.request(
            f"/v1/installs/{encoded}/heartbeats", method="POST", body=request
        )


class OrgsClient:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def find_by_slug(self, slug: str) -> Any:
        return self._transport.request("/v1/orgs", query={"slug": slug})

    def create(self, request: dict[str, Any]) -> Any:
        return self._transport.request("/v1/orgs", method="POST", body=request)

    def get(self, org_id: str) -> Any:
        return self._transport.request(f"/v1/orgs/{encode_path_segment(org_id)}")

    def update(self, org_id: str, request: dict[str, Any]) -> Any:
        return self._transport.request(
            f"/v1/orgs/{encode_path_segment(org_id)}", method="PATCH", body=request
        )

    def create_api_key(self, org_id: str, request: dict[str, Any]) -> Any:
        return self._transport.request(
            f"/v1/orgs/{encode_path_segment(org_id)}/api-keys",
            method="POST",
            body=request,
        )

    def list_api_keys(self, org_id: str) -> Any:
        return self._transport.request(
            f"/v1/orgs/{encode_path_segment(org_id)}/api-keys"
        )

    def revoke_api_key(self, org_id: str, api_key_id: str) -> Any:
        return self._transport.request(
            f"/v1/orgs/{encode_path_segment(org_id)}/api-keys/{encode_path_segment(api_key_id)}",
            method="DELETE",
        )


class PoliciesClient:
    def __init__(self, transport: Transport, *, read_only: bool = False) -> None:
        self._transport = transport
        self._read_only = read_only

    def list(self, *, active: bool, industry: str | None = None) -> Any:
        if active is None:
            raise GlobiguardConfigError("Policies list requires an explicit active filter.")
        return self._transport.request(
            "/v1/policies", query={"industry": industry, "active": active}
        )

    def list_templates(self, industry: str | None = None) -> Any:
        return self._transport.request(
            "/v1/policies/templates",
            query={"industry": industry} if industry else None,
        )

    def get(self, policy_id: str) -> Any:
        return self._transport.request(f"/v1/policies/{encode_path_segment(policy_id)}")

    def create(self, request: dict[str, Any]) -> Any:
        self._require_write("create")
        return self._transport.request("/v1/policies", method="POST", body=request)

    def create_from_template(self, template_id: str) -> Any:
        self._require_write("create_from_template")
        return self._transport.request(
            f"/v1/policies/from-template/{encode_path_segment(template_id)}",
            method="POST",
        )

    def update(self, policy_id: str, request: dict[str, Any]) -> Any:
        self._require_write("update")
        return self._transport.request(
            f"/v1/policies/{encode_path_segment(policy_id)}",
            method="PUT",
            body=request,
        )

    def remove(self, policy_id: str) -> Any:
        self._require_write("remove")
        return self._transport.request(
            f"/v1/policies/{encode_path_segment(policy_id)}", method="DELETE"
        )

    def activate(self, policy_id: str) -> Any:
        self._require_write("activate")
        return self._transport.request(
            f"/v1/policies/{encode_path_segment(policy_id)}/activate",
            method="POST",
        )

    def _require_write(self, method: str) -> None:
        if self._read_only:
            raise GlobiguardConfigError(f"{method} requires a server client.")


class QueueClient:
    def __init__(self, transport: Transport, *, read_only: bool = False) -> None:
        self._transport = transport
        self._read_only = read_only

    def list(self, *, status: str | None = None) -> Any:
        return self._transport.request("/v1/queue", query={"status": status})

    def get(self, queue_entry_id: str) -> Any:
        return self._transport.request(f"/v1/queue/{encode_path_segment(queue_entry_id)}")

    def decide(
        self,
        queue_entry_id: str,
        *,
        action: str,
        reviewed_by: str | None = None,
        notes: str | None = None,
        reason_code: str | None = None,
        modified_payload_summary: dict[str, Any] | None = None,
        assigned_approver_id: str | None = None,
        escalated_by: str | None = None,
    ) -> Any:
        if self._read_only:
            raise GlobiguardConfigError("decide requires a server client.")
        if action not in {"approve", "reject", "modify", "escalate", "resume"}:
            raise GlobiguardConfigError(
                "action must be approve, reject, modify, escalate, or resume."
            )
        if action == "modify" and modified_payload_summary is None:
            raise GlobiguardConfigError(
                "modified_payload_summary is required for modify."
            )
        if action == "escalate" and (not escalated_by or not reason_code):
            raise GlobiguardConfigError(
                "escalated_by and reason_code are required for escalate."
            )
        body: dict[str, Any] = {}
        if action in {"approve", "reject", "modify"}:
            body.update({"reviewedBy": reviewed_by, "notes": notes})
        if action == "modify":
            body.update(
                {
                    "reasonCode": reason_code,
                    "modifiedPayloadSummary": modified_payload_summary,
                }
            )
        if action == "escalate":
            body.update(
                {
                    "assignedApproverId": assigned_approver_id,
                    "escalatedBy": escalated_by,
                    "reasonCode": reason_code,
                    "notes": notes,
                }
            )
        return self._transport.request(
            f"/v1/queue/{encode_path_segment(queue_entry_id)}/{action}",
            method="POST",
            body={key: value for key, value in body.items() if value is not None},
        )


class WorkflowsClient:
    def __init__(self, transport: Transport, *, read_only: bool = False) -> None:
        self._transport = transport
        self._read_only = read_only

    def list(self, *, active: bool) -> Any:
        if active is None:
            raise GlobiguardConfigError("Workflow list requires an explicit active filter.")
        return self._transport.request("/v1/workflows", query={"active": active})

    def get(self, workflow_id: str) -> Any:
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}"
        )

    def create(self, request: dict[str, Any]) -> Any:
        self._require_write("create")
        return self._transport.request("/v1/workflows", method="POST", body=request)

    def update(self, workflow_id: str, request: dict[str, Any]) -> Any:
        self._require_write("update")
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}",
            method="PUT",
            body=request,
        )

    def remove(self, workflow_id: str) -> Any:
        self._require_write("remove")
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}", method="DELETE"
        )

    def activate(self, workflow_id: str) -> Any:
        self._require_write("activate")
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}/activate",
            method="POST",
        )

    def run(self, workflow_id: str, trigger_data: dict[str, Any] | None = None) -> Any:
        self._require_write("run")
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}/run",
            method="POST",
            body=trigger_data or {},
        )

    def list_runs(self, workflow_id: str) -> Any:
        return self._transport.request(
            f"/v1/workflows/{encode_path_segment(workflow_id)}/runs"
        )

    def _require_write(self, method: str) -> None:
        if self._read_only:
            raise GlobiguardConfigError(f"{method} requires a server client.")
