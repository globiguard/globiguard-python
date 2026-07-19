from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from datetime import UTC, datetime
from typing import Any

import globiguard
from globiguard.errors import GlobiguardAuthorityError, GlobiguardConfigError
from globiguard.transport import join_url


class FakeResponse:
    def __init__(self, *, status: int = 200, body: bytes = b"{}", headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.headers = headers or {"content-type": "application/json"}
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: Any) -> None:
        return None


class RecordingOpener:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    def __call__(self, request: Any, *, timeout: float) -> FakeResponse:
        self.requests.append((request, timeout))
        return FakeResponse(body=b'{"ok":true}')


class GlobiguardSdkTests(unittest.TestCase):
    def test_bootstrap_helpers_enforce_install_reporting_contract(self) -> None:
        profile = {
            "environment": "sandbox",
            "deploymentMode": "self_hosted",
            "issuerMode": "customer_issued",
            "installReporting": "opt_in",
            "installLabel": "Python worker",
            "installFingerprint": "fp_123",
        }

        request = globiguard.build_install_registration_request(
            profile,  # type: ignore[arg-type]
            package_name="globiguard",
            package_version="0.1.0",
            integration_kind="sdk",
            runtime_kind="python",
            metadata={"python": "3.12"},
        )

        self.assertEqual(request["environment"], "sandbox")
        self.assertEqual(request["deploymentMode"], "self_hosted")
        self.assertEqual(request["issuerMode"], "customer_issued")
        self.assertEqual(request["installReporting"], "opt_in")

        with self.assertRaises(GlobiguardConfigError):
            globiguard.resolve_bootstrap_profile(
                {
                    "environment": "live",
                    "deploymentMode": "hosted",
                    "issuerMode": "customer_issued",
                    "installReporting": "default",
                }  # type: ignore[arg-type]
            )

    def test_server_client_uses_secret_headers_and_reserved_headers_are_protected(self) -> None:
        opener = RecordingOpener()
        client = globiguard.create_server_client(
            environment="sandbox",
            services={"controlPlane": "https://api.globiguard.com"},
            credential=globiguard.SecretCredential(
                project_id="proj_123", token="sk_secret", environment="sandbox"
            ),
            opener=opener,
        )

        client.control_plane.request(
            "/v1/audit",
            headers={"x-globiguard-secret-key": "attacker", "x-custom": "ok"},
        )

        request, timeout = opener.requests[0]
        headers = dict(request.header_items())
        self.assertEqual(timeout, 10.0)
        self.assertEqual(headers["X-globiguard-secret-key"], "sk_secret")
        self.assertEqual(headers["X-globiguard-project-id"], "proj_123")
        self.assertEqual(headers["X-globiguard-environment"], "sandbox")
        self.assertEqual(headers["X-custom"], "ok")

    def test_credentials_do_not_leak_tokens_in_repr(self) -> None:
        credential = globiguard.SecretCredential(
            project_id="proj_123", token="sk_secret", environment="live"
        )
        self.assertNotIn("sk_secret", repr(credential))
        self.assertIn("<redacted>", repr(credential))

    def test_rejects_unsafe_urls_and_paths(self) -> None:
        with self.assertRaises(GlobiguardConfigError):
            globiguard.create_server_client(
                environment="live",
                services={"controlPlane": "http://api.globiguard.com"},
                credential=globiguard.SecretCredential(
                    project_id="proj_123", token="sk_secret", environment="live"
                ),
            )
        with self.assertRaises(GlobiguardConfigError):
            join_url("https://api.globiguard.com", "https://evil.test/v1/audit")
        with self.assertRaises(GlobiguardConfigError):
            join_url("https://api.globiguard.com", "/v1/../admin")
        with self.assertRaises(GlobiguardConfigError):
            join_url("https://api.globiguard.com", "/v1/%2e%2e/admin")
        with self.assertRaises(GlobiguardConfigError):
            join_url("https://api.globiguard.com", "/v1/%ZZ/admin")
        with self.assertRaises(GlobiguardConfigError):
            join_url("https://api.globiguard.com", "/v1/audit?x=1")

    def test_webhook_verification_requires_raw_signed_body(self) -> None:
        raw_body = json.dumps(
            {
                "contractVersion": "2026-05-trust-webhook-beta",
                "id": "del_123",
                "timestamp": "2026-05-29T10:30:00Z",
                "type": "approval.approved",
                "apiFamily": "webhooks.v1",
                "data": {"approvalId": "appr_123"},
            },
            separators=(",", ":"),
        )
        headers = {
            "x-globiguard-delivery-id": "del_123",
            "x-globiguard-timestamp": "2026-05-29T10:30:00Z",
            "x-globiguard-event-type": "approval.approved",
        }
        payload = globiguard.build_signed_webhook_payload(
            {
                "deliveryId": "del_123",
                "timestamp": "2026-05-29T10:30:00Z",
                "eventType": "approval.approved",
            },
            raw_body,
        )
        signature = hmac.new(b"whsec_test", payload.encode("utf-8"), hashlib.sha256).hexdigest()
        result = globiguard.verify_trust_webhook(
            headers={**headers, "x-globiguard-signature": f"v1={signature}"},
            raw_body=raw_body.encode("utf-8"),
            signing_secret="whsec_test",
            now=datetime(2026, 5, 29, 10, 30, 1, tzinfo=UTC),
        )

        self.assertTrue(result["ok"])
        self.assertFalse(result["duplicateDelivery"])
        self.assertEqual(result["deliveryId"], "del_123")

    def test_idempotency_key_matches_wire_contract_shape(self) -> None:
        key = globiguard.derive_action_idempotency_key(
            stable_seed="order_123",
            action_type="refund",
            actor_id="user_123",
            payload_sha256="abc",
            window_bucket="2026-05-29T10",
        )
        self.assertRegex(key, r"^gg_idem_[0-9a-f]{48}$")

    def test_authorize_or_throw_preserves_fail_closed_semantics(self) -> None:
        class Actions:
            def __init__(self, decision: Any) -> None:
                self.decision = decision

            def authorize(self, _request: dict[str, Any]) -> dict[str, Any]:
                return self.decision  # type: ignore[no-any-return]

        for decision_name in ("ALLOW", "MODIFY"):
            with self.subTest(decision=decision_name):
                governed = globiguard.GovernedActionsClient(
                    actions=Actions({"decision": decision_name}),  # type: ignore[arg-type]
                    audit=object(),  # type: ignore[arg-type]
                    queue=object(),  # type: ignore[arg-type]
                )
                result = governed.authorize_action_or_throw({"actionType": "refund"})
                self.assertEqual(result["decision"], decision_name)

        for decision, expected_kind in (
            ({"decision": "QUEUE", "queueEntryId": "queue_123"}, "QUEUED_FOR_REVIEW"),
            ({"decision": "BLOCK"}, "POLICY_BLOCKED"),
            ({"decision": "UNKNOWN"}, "CONTROL_PLANE_UNAVAILABLE"),
            ({}, "CONTROL_PLANE_UNAVAILABLE"),
            ([], "CONTROL_PLANE_UNAVAILABLE"),
        ):
            with self.subTest(decision=decision):
                governed = globiguard.GovernedActionsClient(
                    actions=Actions(decision),  # type: ignore[arg-type]
                    audit=object(),  # type: ignore[arg-type]
                    queue=object(),  # type: ignore[arg-type]
                )
                with self.assertRaises(GlobiguardAuthorityError) as error:
                    governed.authorize_action_or_throw({"actionType": "refund"})
                self.assertEqual(error.exception.kind, expected_kind)

    def test_verifies_signed_entitlement_manifest_and_rejects_tampering(self) -> None:
        public_key = "0EBi8A20QIJf5lwzzj98ZK1X8EzBJ2nli7rsMM8JXzc"
        manifest = {
            "serialization": "jws-compact",
            "token": (
                "eyJhbGciOiJFZERTQSIsImtpZCI6ImtpZF90ZXN0IiwidHlwIjoiZ2xvYmlndWFyZC5lbnRpdGxlbWVudC52MSJ9."
                "eyJtYW5pZmVzdFR5cGUiOiJnbG9iaWd1YXJkLmVudGl0bGVtZW50LnYxIiwibWFuaWZlc3RWZXJzaW9uIjoxLCJtYW5pZmVzdElkIjoibWFuaWZlc3RfMTIzIiwiaXNzdWVyIjoiaHR0cHM6Ly9hcGkuZ2xvYmlndWFyZC5jb20iLCJpc3N1ZWRBdCI6IjIwMjYtMDUtMjlUMTA6MDA6MDBaIiwibm90QmVmb3JlIjoiMjAyNi0wNS0yOVQxMDowMDowMFoiLCJleHBpcmVzQXQiOiIyMDI2LTA1LTMwVDEwOjAwOjAwWiIsInN1YmplY3QiOnsib3JnSWQiOiJvcmdfMTIzIiwid29ya3NwYWNlTmFtZSI6IkFjbWUiLCJvcmdTbHVnIjoiYWNtZSIsInByb2plY3RJZCI6InByb2pfMTIzIiwicHJvamVjdFNsdWciOiJtYWluIiwiZW52aXJvbm1lbnQiOiJzYW5kYm94IiwiZGVwbG95bWVudE1vZGUiOiJzZWxmX2hvc3RlZCJ9LCJjb21tZXJjaWFsIjp7ImNvbW1lcmNpYWxQbGFuIjoiR1JPV1RIIiwiYmlsbGluZ1N0YXR1cyI6IkFDVElWRSIsInBpbG90QWN0aXZlIjpmYWxzZX0sImVudGl0bGVtZW50cyI6eyJpbmNsdWRlZFF1ZXJpZXNQZXJNb250aCI6MTAwMDAsImZyYW1ld29ya1Nsb3RzIjozLCJvdmVyYWdlTW9kZSI6Ik1FVEVSRUQifX0."
                "qJZVmhIyLBsSUmrFlpCzCytt6pUly5CZG7miWgxxZttuqXNnNWfleiSJ7ScK15AVhY0ZnLopSHZg4_uQbSi8CQ"
            ),
            "protected": {
                "alg": "EdDSA",
                "kid": "kid_test",
                "typ": "globiguard.entitlement.v1",
            },
            "payload": {
                "manifestType": "globiguard.entitlement.v1",
                "manifestVersion": 1,
                "manifestId": "manifest_123",
                "issuer": "https://api.globiguard.com",
                "issuedAt": "2026-05-29T10:00:00Z",
                "notBefore": "2026-05-29T10:00:00Z",
                "expiresAt": "2026-05-30T10:00:00Z",
                "subject": {
                    "orgId": "org_123",
                    "workspaceName": "Acme",
                    "orgSlug": "acme",
                    "projectId": "proj_123",
                    "projectSlug": "main",
                    "environment": "sandbox",
                    "deploymentMode": "self_hosted",
                },
                "commercial": {
                    "commercialPlan": "GROWTH",
                    "billingStatus": "ACTIVE",
                    "pilotActive": False,
                },
                "entitlements": {
                    "includedQueriesPerMonth": 10000,
                    "frameworkSlots": 3,
                    "overageMode": "METERED",
                },
            },
        }

        payload = globiguard.verify_signed_entitlement_manifest(
            manifest,
            public_keys_by_id={"kid_test": public_key},
            expected_issuer="https://api.globiguard.com",
            expected_org_id="org_123",
            expected_project_id="proj_123",
            expected_environment="sandbox",
            expected_deployment_mode="self_hosted",
            now=datetime(2026, 5, 29, 10, 30, 0, tzinfo=UTC),
        )

        self.assertEqual(payload["commercial"]["commercialPlan"], "GROWTH")

        tampered = {**manifest, "payload": {**manifest["payload"], "issuer": "evil"}}
        with self.assertRaises(GlobiguardConfigError):
            globiguard.verify_signed_entitlement_manifest(
                tampered,
                public_keys_by_id={"kid_test": public_key},
                now=datetime(2026, 5, 29, 10, 30, 0, tzinfo=UTC),
            )


if __name__ == "__main__":
    unittest.main()
