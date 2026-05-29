from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from .errors import GlobiguardConfigError

GLOBIGUARD_ENTITLEMENT_MANIFEST_TYPE = "globiguard.entitlement.v1"
GLOBIGUARD_ENTITLEMENT_SIGNING_ALGORITHM = "EdDSA"
GLOBIGUARD_ENTITLEMENT_SERIALIZATION = "jws-compact"

_COMMERCIAL_PLANS = {"FREE", "STARTER", "GROWTH", "SCALE", "ENTERPRISE"}
_BILLING_STATUSES = {"FREE", "PILOT", "ACTIVE", "GRACE", "PAST_DUE", "SUSPENDED", "CANCELED"}
_OVERAGE_MODES = {"NONE", "METERED", "CONTRACT"}
_OFFLINE_DEPLOYMENT_MODES = {"self_hosted", "sovereign"}
_MANIFEST_ENVIRONMENTS = {"sandbox", "live"}

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
_IDENTITY = (0, 1)


def verify_signed_entitlement_manifest(
    manifest: dict[str, Any],
    *,
    public_keys_by_id: dict[str, str],
    expected_issuer: str | None = None,
    expected_org_id: str | None = None,
    expected_project_id: str | None = None,
    expected_environment: str | None = None,
    expected_deployment_mode: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    decoded = _decode_manifest_token(str(manifest.get("token", "")))

    if manifest.get("serialization") != GLOBIGUARD_ENTITLEMENT_SERIALIZATION:
        raise GlobiguardConfigError("Unsupported entitlement manifest serialization.")
    if manifest.get("protected") != decoded["protected"]:
        raise GlobiguardConfigError(
            "Entitlement manifest protected header does not match the signed token."
        )
    if manifest.get("payload") != decoded["payload"]:
        raise GlobiguardConfigError(
            "Entitlement manifest payload does not match the signed token."
        )

    key_id = decoded["protected"]["kid"]
    raw_public_key = public_keys_by_id.get(key_id)
    if not raw_public_key:
        raise GlobiguardConfigError(f'Unknown entitlement manifest signing key "{key_id}".')

    if not _verify_ed25519(
        _decode_base64url(raw_public_key),
        decoded["signing_input"].encode("utf-8"),
        decoded["signature"],
    ):
        raise GlobiguardConfigError("Entitlement manifest signature verification failed.")

    payload = decoded["payload"]
    current_time = now or datetime.now(UTC)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=UTC)

    issued_at = _parse_iso_date(payload.get("issuedAt"), "issuedAt")
    not_before = _parse_iso_date(payload.get("notBefore"), "notBefore")
    expires_at = _parse_iso_date(payload.get("expiresAt"), "expiresAt")
    if issued_at > expires_at:
        raise GlobiguardConfigError("Entitlement manifest timestamps are inconsistent.")
    if not_before > current_time:
        raise GlobiguardConfigError("Entitlement manifest is not active yet.")
    if expires_at <= current_time:
        raise GlobiguardConfigError("Entitlement manifest has expired.")

    subject = payload["subject"]
    if expected_issuer and payload["issuer"] != expected_issuer:
        raise GlobiguardConfigError(
            "Entitlement manifest issuer does not match the expected issuer."
        )
    if expected_org_id and subject["orgId"] != expected_org_id:
        raise GlobiguardConfigError(
            "Entitlement manifest workspace does not match the expected workspace."
        )
    if expected_project_id and subject["projectId"] != expected_project_id:
        raise GlobiguardConfigError(
            "Entitlement manifest project does not match the expected project."
        )
    if expected_environment and subject["environment"] != expected_environment:
        raise GlobiguardConfigError(
            "Entitlement manifest environment does not match the expected environment."
        )
    if expected_deployment_mode and subject["deploymentMode"] != expected_deployment_mode:
        raise GlobiguardConfigError(
            "Entitlement manifest deployment mode does not match the expected deployment mode."
        )

    return payload


def _decode_manifest_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise GlobiguardConfigError("Invalid entitlement manifest token.")
    encoded_header, encoded_payload, encoded_signature = parts
    protected = _decode_json(encoded_header, "Invalid entitlement manifest protected header.")
    payload = _decode_json(encoded_payload, "Invalid entitlement manifest payload.")

    if (
        protected.get("alg") != GLOBIGUARD_ENTITLEMENT_SIGNING_ALGORITHM
        or protected.get("typ") != GLOBIGUARD_ENTITLEMENT_MANIFEST_TYPE
        or not protected.get("kid")
    ):
        raise GlobiguardConfigError("Unsupported entitlement manifest protected header.")
    if (
        payload.get("manifestType") != GLOBIGUARD_ENTITLEMENT_MANIFEST_TYPE
        or payload.get("manifestVersion") != 1
    ):
        raise GlobiguardConfigError("Unsupported entitlement manifest payload.")
    _validate_manifest_payload(payload)
    return {
        "protected": protected,
        "payload": payload,
        "signature": _decode_base64url(encoded_signature),
        "signing_input": f"{encoded_header}.{encoded_payload}",
    }


def _validate_manifest_payload(payload: dict[str, Any]) -> None:
    for field in ("manifestId", "issuer", "issuedAt", "notBefore", "expiresAt"):
        _require_non_empty_string(payload.get(field), field)
    subject = payload.get("subject")
    commercial = payload.get("commercial")
    entitlements = payload.get("entitlements")
    if not isinstance(subject, dict) or not isinstance(commercial, dict) or not isinstance(entitlements, dict):
        raise GlobiguardConfigError("Entitlement manifest payload is incomplete.")

    for field in ("orgId", "workspaceName", "orgSlug", "projectId", "projectSlug"):
        _require_non_empty_string(subject.get(field), f"subject.{field}")
    if subject.get("environment") not in _MANIFEST_ENVIRONMENTS:
        raise GlobiguardConfigError('Entitlement manifest field "subject.environment" is invalid.')
    if subject.get("deploymentMode") not in _OFFLINE_DEPLOYMENT_MODES:
        raise GlobiguardConfigError('Entitlement manifest field "subject.deploymentMode" is invalid.')
    if commercial.get("commercialPlan") not in _COMMERCIAL_PLANS:
        raise GlobiguardConfigError('Entitlement manifest field "commercial.commercialPlan" is invalid.')
    if commercial.get("billingStatus") not in _BILLING_STATUSES:
        raise GlobiguardConfigError('Entitlement manifest field "commercial.billingStatus" is invalid.')
    if not isinstance(commercial.get("pilotActive"), bool):
        raise GlobiguardConfigError('Entitlement manifest field "commercial.pilotActive" is invalid.')
    _require_nullable_non_negative_integer(
        entitlements.get("includedQueriesPerMonth"),
        "entitlements.includedQueriesPerMonth",
    )
    _require_nullable_non_negative_integer(
        entitlements.get("frameworkSlots"),
        "entitlements.frameworkSlots",
    )
    if entitlements.get("overageMode") not in _OVERAGE_MODES:
        raise GlobiguardConfigError('Entitlement manifest field "entitlements.overageMode" is invalid.')


def _parse_iso_date(value: object, field_name: str) -> datetime:
    if not value:
        raise GlobiguardConfigError(f'Entitlement manifest field "{field_name}" must be present.')
    if not isinstance(value, str):
        raise GlobiguardConfigError(
            f'Entitlement manifest field "{field_name}" must be a valid ISO timestamp.'
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GlobiguardConfigError(
            f'Entitlement manifest field "{field_name}" must be a valid ISO timestamp.'
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _require_non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or len(value) == 0:
        raise GlobiguardConfigError(
            f'Entitlement manifest field "{field_name}" must be a non-empty string.'
        )


def _require_nullable_non_negative_integer(value: object, field_name: str) -> None:
    if value is None:
        return
    if not isinstance(value, int) or value < 0:
        raise GlobiguardConfigError(
            f'Entitlement manifest field "{field_name}" must be a non-negative integer or null.'
        )


def _decode_json(value: str, message: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_decode_base64url(value).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise GlobiguardConfigError(message) from exc
    if not isinstance(decoded, dict):
        raise GlobiguardConfigError(message)
    return decoded


def _decode_base64url(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise GlobiguardConfigError("Invalid base64url value.") from exc


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = _decode_point(public_key)
        r_point = _decode_point(signature[:32])
    except GlobiguardConfigError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(signature[:32] + public_key + message), "little") % _L
    return _scalar_mult(_B, s) == _point_add(r_point, _scalar_mult(public_point, h))


def _decode_point(value: bytes) -> tuple[int, int]:
    y = int.from_bytes(value, "little") & ((1 << 255) - 1)
    sign = value[31] >> 7
    if y >= _Q:
        raise GlobiguardConfigError("Invalid Ed25519 point.")
    x = _recover_x(y, sign)
    point = (x, y)
    if not _is_on_curve(point):
        raise GlobiguardConfigError("Invalid Ed25519 point.")
    return point


def _recover_x(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q != 0:
        raise GlobiguardConfigError("Invalid Ed25519 point.")
    if (x & 1) != sign:
        x = _Q - x
    return x


def _point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    denominator_x = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    denominator_y = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = ((x1 * y2 + x2 * y1) * denominator_x) % _Q
    y3 = ((y1 * y2 + x1 * x2) * denominator_y) % _Q
    return x3, y3


def _scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _is_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _sha512(value: bytes) -> bytes:
    import hashlib

    return hashlib.sha512(value).digest()
