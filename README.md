# globiguard-python

Official dependency-minimal Python SDK for GlobiGuard.

This package provides a small, auditable integration surface for production services. It intentionally uses the Python standard library for runtime behavior: no `requests`, no `httpx`, no pydantic, no framework dependency, and no hidden telemetry.

## What is included

- Server and browser-style clients with the same auth headers as the TypeScript SDK.
- Resource clients for actions, audit, installs, orgs/API keys, policies, queue, and workflows.
- Governed action helpers for authorize-or-throw, approval polling, correlation IDs, and idempotency keys.
- Bootstrap install registration/heartbeat builders for hosted, self-hosted, and sovereign deployment modes.
- Offline entitlement manifest verification for customer-controlled deployments.
- Server-only trust webhook verification using raw request bodies and HMAC-SHA256.
- Typed package marker (`py.typed`) and a small, inspectable source layout.

## Install

```bash
pip install globiguard
```

Until the first PyPI release, install from the repository root:

```bash
python -m pip install .
```

## Authentication and keys

GlobiGuard project IDs, secret keys, publishable keys, local credentials, and webhook signing secrets are issued by the GlobiGuard app/control plane. The Python SDK uses the same wire headers as the TypeScript SDK:

| Credential | Headers |
| --- | --- |
| Secret | `x-globiguard-project-id`, `x-globiguard-secret-key` |
| Publishable | `x-globiguard-project-id`, `x-globiguard-publishable-key` |
| Local | `x-globiguard-local-mode`, optional `x-globiguard-local-token` |
| All clients | `x-globiguard-client`, `x-globiguard-environment` |

Server clients only accept secret or local credentials. Publishable keys are limited to read-only/browser-style clients. Local credentials only work with `environment="local"` and localhost/loopback service URLs.

## Server client

```python
import globiguard

client = globiguard.create_server_client(
    environment="sandbox",
    services={"controlPlane": "https://api.globiguard.com"},
    credential=globiguard.SecretCredential(
        project_id="proj_123",
        token="sk_live_...",
        environment="sandbox",
    ),
)

decision = client.governed_actions.authorize_action_or_throw(
    {
        "context": {
            "actionType": "refund.create",
            "destination": {
                "type": "custom",
                "name": "payments-production",
            },
            "dataClasses": ["CONFIDENTIAL"],
            "actor": {
                "id": "support-agent-123",
                "type": "agent",
            },
            "purpose": "Resolve an approved customer escalation",
            "correlationId": "case_456",
            "idempotencyKey": "case_456:refund:v1",
        }
    }
)
```

Optional action gateway routing matches the TypeScript SDK:

```python
client = globiguard.create_server_client(
    environment="local",
    services={
        "controlPlane": "http://localhost:3000",
        "sidecar": "http://localhost:8787",
    },
    credential=globiguard.LocalCredential(token="dev-token"),
    action_gateway=globiguard.ActionGatewayConfig(mode="sidecar"),
)
```

## Resource clients

```python
client.actions.authorize({...})
client.actions.get_authorization("auth_123")
client.actions.create_approval({...})
client.actions.list_evidence(authorization_id="auth_123")

client.audit.list(from_="2026-05-01T00:00:00Z", limit=50)
client.audit.export({"format": "json"})
client.audit.get_evidence_package_summary("pkg_123")
client.audit.get_incident_replay(correlation_id="corr_123")

client.installs.register({...})
client.installs.heartbeat("install_123", {...})

client.orgs.find_by_slug("acme")
client.orgs.create_api_key("org_123", {...})
client.orgs.revoke_api_key("org_123", "key_123")

client.policies.list(active=True)
client.policies.create_from_template("tpl_123")
client.policies.activate("pol_123")

client.queue.list(status="PENDING")
client.queue.decide("queue_123", action="approve", reviewed_by="user_123")
client.queue.decide(
    "queue_456",
    action="modify",
    reviewed_by="user_123",
    reason_code="REMOVE_SSN",
    modified_payload_summary={
        "sha256": "reviewed-payload-digest",
        "fieldTypes": ["CUSTOMER_ID"],
    },
)

client.workflows.list(active=True)
client.workflows.run("wf_123", {"source": "python"})
client.workflows.list_runs("wf_123")
```

## Bootstrap installs

Bootstrap helpers keep install registration and heartbeat payloads aligned with the hosted/self-hosted/sovereign deployment contract.

```python
profile = {
    "environment": "sandbox",
    "deploymentMode": "self_hosted",
    "issuerMode": "customer_issued",
    "installReporting": "opt_in",
    "installLabel": "Python worker",
}

registration = globiguard.build_install_registration_request(
    profile,
    package_name="globiguard",
    package_version="0.1.0",
    integration_kind="sdk",
    runtime_kind="python",
)
```

Hosted deployments must use `globiguard_issued`. Self-hosted and sovereign deployments must use `customer_issued` and explicitly choose `opt_in` or `disabled` install reporting.

## Offline entitlement manifests

Customer-controlled deployments can verify signed entitlement manifests without calling GlobiGuard at runtime.

```python
payload = globiguard.verify_signed_entitlement_manifest(
    manifest,
    public_keys_by_id={"kid_2026_05": "<base64url-ed25519-public-key>"},
    expected_issuer="https://api.globiguard.com",
    expected_org_id="org_123",
    expected_project_id="proj_123",
    expected_environment="live",
    expected_deployment_mode="self_hosted",
)
```

The verifier checks compact JWS structure, protected header/payload consistency, Ed25519 signature, manifest schema, timestamp validity, and optional issuer/workspace/project/environment/deployment expectations.

## Webhook verification

Pass the exact raw request body bytes received from your framework. Do not parse and re-serialize JSON before verification; whitespace, key order, and line endings are part of the signed payload.

```python
result = globiguard.verify_trust_webhook(
    headers=request.headers,
    raw_body=request.get_data(),
    signing_secret="whsec_...",
)

if not result["ok"]:
    raise ValueError(result["error"]["message"])

event = result["envelope"]
```

Webhook verification checks required headers, timestamp replay window, envelope/header consistency, and `v1=` HMAC signatures using constant-time comparison.

## Security posture

- Runtime dependencies: **zero**.
- HTTPS is required outside `local`.
- Local credentials require localhost or loopback URLs.
- Reserved GlobiGuard auth headers cannot be overridden by per-request headers.
- Credential `repr()` output redacts tokens.
- Request paths reject absolute URLs, query strings, fragments, backslashes, invalid percent encoding, and dot segments.
- HTTP requests use explicit timeouts.
- Entitlement manifests verify Ed25519 signatures locally without a crypto package dependency.

Known gap: the main app has two adjacent key surfaces: workspace API keys under `/app/api-keys` and SDK project credentials under `/projects/:projectId/credentials`. Python integrations need the SDK project credentials (`sandbox` or `live`) so the UI/docs should make that distinction very clear.

## Development

```bash
set PYTHONPATH=src
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m pip install --no-deps --no-build-isolation .
```
