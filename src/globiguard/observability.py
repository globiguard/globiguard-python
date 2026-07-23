"""Observability client — traces, evidence, metrics, dashboard."""
from __future__ import annotations
from typing import Any
from .transport import Transport


class ObservabilityClient:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    def get_dashboard(self, **query: Any) -> dict[str, Any]:
        return self._transport.request("/v1/observability/dashboard", method="GET", query=query or None)

    def get_traces(self, **query: Any) -> dict[str, Any]:
        return self._transport.request("/v1/observability/traces", method="GET", query=query or None)

    def get_trace(self, trace_id: str) -> dict[str, Any]:
        return self._transport.request(f"/v1/observability/traces/{trace_id}", method="GET")

    def get_evidence_detail(self, evidence_package_id: str) -> dict[str, Any]:
        return self._transport.request(f"/v1/observability/evidence/{evidence_package_id}", method="GET")

    def get_metrics(self, **query: Any) -> dict[str, Any]:
        return self._transport.request("/v1/observability/metrics", method="GET", query=query or None)
