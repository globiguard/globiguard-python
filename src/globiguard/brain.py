"""Brain (entity detection) client."""
from __future__ import annotations
from typing import Any
from .transport import Transport


class BrainClient:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def scan(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._transport.request("/v1/brain/scan", method="POST", body=request)

    def redact(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._transport.request("/v1/brain/redact", method="POST", body=request)

    def classify(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._transport.request("/v1/brain/classify", method="POST", body=request)
