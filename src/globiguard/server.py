from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

GLOBIGUARD_TRUST_WEBHOOK_CONTRACT_VERSION = "2026-05-trust-webhook-beta"
GLOBIGUARD_TRUST_WEBHOOK_SIGNATURE_SCHEME = "globiguard-hmac-sha256-v1"
GLOBIGUARD_TRUST_WEBHOOK_HEADER_NAMES = {
    "deliveryId": "x-globiguard-delivery-id",
    "timestamp": "x-globiguard-timestamp",
    "eventType": "x-globiguard-event-type",
    "signature": "x-globiguard-signature",
}


def verify_trust_webhook(
    *,
    headers: Mapping[str, str],
    raw_body: str | bytes,
    signing_secret: str,
    tolerance_seconds: int = 300,
    now: datetime | None = None,
    seen_delivery: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    normalized_headers = _normalize_headers(headers)
    body_text = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body

    if not all(
        [
            normalized_headers["deliveryId"],
            normalized_headers["timestamp"],
            normalized_headers["eventType"],
            normalized_headers["signature"],
        ]
    ):
        return _verification_failure(
            "Missing required GlobiGuard webhook headers.", normalized_headers
        )

    timestamp = _parse_timestamp(normalized_headers["timestamp"])
    if timestamp is None:
        return _verification_failure(
            "Invalid GlobiGuard webhook timestamp.", normalized_headers
        )

    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=UTC)
    age_seconds = abs((current_time - timestamp).total_seconds())
    if age_seconds > tolerance_seconds:
        return _verification_failure(
            "GlobiGuard webhook timestamp is outside the accepted replay window.",
            normalized_headers,
        )

    try:
        envelope = json.loads(body_text)
    except json.JSONDecodeError:
        return _verification_failure(
            "GlobiGuard webhook body is not valid JSON.", normalized_headers
        )

    if (
        envelope.get("id") != normalized_headers["deliveryId"]
        or envelope.get("type") != normalized_headers["eventType"]
    ):
        return _verification_failure(
            "GlobiGuard webhook headers do not match the signed envelope.",
            normalized_headers,
        )

    expected_signature = hmac.new(
        signing_secret.encode("utf-8"),
        build_signed_webhook_payload(normalized_headers, body_text).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    provided_signature = _normalize_signature(normalized_headers["signature"])
    if not hmac.compare_digest(expected_signature, provided_signature):
        return _verification_failure(
            "Invalid GlobiGuard webhook signature.", normalized_headers
        )

    delivery_id = normalized_headers["deliveryId"]
    duplicate_delivery = seen_delivery(delivery_id) if seen_delivery else False
    return {
        "ok": True,
        "deliveryId": delivery_id,
        "eventType": normalized_headers["eventType"],
        "timestamp": normalized_headers["timestamp"],
        "envelope": envelope,
        "duplicateDelivery": duplicate_delivery,
    }


def build_signed_webhook_payload(headers: Mapping[str, str], raw_body: str) -> str:
    return ".".join(
        [
            GLOBIGUARD_TRUST_WEBHOOK_SIGNATURE_SCHEME,
            headers["deliveryId"],
            headers["timestamp"],
            headers["eventType"],
            raw_body,
        ]
    )


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    lower_headers = {key.lower(): value for key, value in headers.items()}
    return {
        "deliveryId": lower_headers.get(
            GLOBIGUARD_TRUST_WEBHOOK_HEADER_NAMES["deliveryId"], ""
        ),
        "timestamp": lower_headers.get(
            GLOBIGUARD_TRUST_WEBHOOK_HEADER_NAMES["timestamp"], ""
        ),
        "eventType": lower_headers.get(
            GLOBIGUARD_TRUST_WEBHOOK_HEADER_NAMES["eventType"], ""
        ),
        "signature": lower_headers.get(
            GLOBIGUARD_TRUST_WEBHOOK_HEADER_NAMES["signature"], ""
        ),
    }


def _normalize_signature(signature: str) -> str:
    return signature[3:] if signature.startswith("v1=") else signature


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _verification_failure(
    message: str, headers: Mapping[str, str]
) -> dict[str, Any]:
    return {
        "ok": False,
        "deliveryId": headers.get("deliveryId") or None,
        "eventType": headers.get("eventType") or None,
        "timestamp": headers.get("timestamp") or None,
        "error": {
            "kind": "WEBHOOK_VERIFICATION_FAILED",
            "message": message,
            "safeDetails": {"boundary": "server"},
        },
    }
