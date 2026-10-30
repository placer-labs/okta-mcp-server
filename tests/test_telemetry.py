# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the OpenTelemetry telemetry helpers.

These cover the pure logic (endpoint gating, swallowed-error detection) and a
middleware pass-through smoke test using the default no-op OTel providers, so no
live OTLP collector is required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from okta_mcp_server.utils import telemetry


@dataclass
class _Block:
    text: str


@dataclass
class _FakeResult:
    content: list = field(default_factory=list)
    structured_content: Any = None


@dataclass
class _FakeMessage:
    name: str


@dataclass
class _FakeContext:
    message: _FakeMessage


def test_telemetry_disabled_without_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert telemetry.telemetry_enabled() is False
    assert telemetry.configure_telemetry() is False


def test_telemetry_enabled_reads_env(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    assert telemetry.telemetry_enabled() is True


def test_http_tracing_defaults_on_and_toggles(monkeypatch):
    monkeypatch.delenv("OKTA_MCP_HTTP_TRACING", raising=False)
    assert telemetry.http_tracing_enabled() is True
    monkeypatch.setenv("OKTA_MCP_HTTP_TRACING", "false")
    assert telemetry.http_tracing_enabled() is False


def test_suppress_health_probes_defaults_on_and_toggles(monkeypatch):
    monkeypatch.delenv("OKTA_MCP_SUPPRESS_HEALTH_PROBES", raising=False)
    assert telemetry.suppress_health_probes() is True
    monkeypatch.setenv("OKTA_MCP_SUPPRESS_HEALTH_PROBES", "0")
    assert telemetry.suppress_health_probes() is False


def test_loguru_patcher_injects_trace_ids():
    from opentelemetry.sdk.trace import TracerProvider

    tracer = TracerProvider().get_tracer("test")  # local provider, valid spans
    record = {"extra": {}}
    with tracer.start_as_current_span("s"):
        telemetry._otel_loguru_patcher(record)
    assert len(record["extra"]["trace_id"]) == 32
    assert len(record["extra"]["span_id"]) == 16


def test_loguru_patcher_noop_without_active_span():
    record = {"extra": {}}
    telemetry._otel_loguru_patcher(record)
    assert record["extra"] == {}


@pytest.mark.parametrize(
    "result,expected",
    [
        (_FakeResult(content=[_Block("Exception: boom")]), True),
        (_FakeResult(content=[_Block("Error: nope")]), True),
        (_FakeResult(content=[_Block("  Exception: leading space")]), True),
        (_FakeResult(structured_content={"error": "Error: x"}), True),
        (_FakeResult(content=[_Block("Successfully retrieved 5 groups")]), False),
        (_FakeResult(structured_content={"users_count": 3}), False),
        (_FakeResult(content=[]), False),
    ],
)
def test_result_is_error_detection(result, expected):
    assert telemetry._result_is_error(result) is expected


@pytest.mark.asyncio
async def test_middleware_passes_result_through():
    """on_call_tool must return the wrapped result unchanged (no-op providers)."""
    mw = telemetry.build_tool_middleware()
    sentinel = _FakeResult(content=[_Block("Successfully retrieved 5 groups")])

    async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
        return sentinel

    out = await mw.on_call_tool(_FakeContext(_FakeMessage("list_groups")), call_next)
    assert out is sentinel


@pytest.mark.asyncio
async def test_middleware_handles_error_result_without_raising():
    mw = telemetry.build_tool_middleware()
    err = _FakeResult(content=[_Block("Exception: ValidationError ...")])

    async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
        return err

    out = await mw.on_call_tool(_FakeContext(_FakeMessage("list_group_apps")), call_next)
    assert out is err


@pytest.mark.asyncio
async def test_middleware_reraises_exceptions():
    mw = telemetry.build_tool_middleware()

    async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError, match="kaboom"):
        await mw.on_call_tool(_FakeContext(_FakeMessage("list_users")), call_next)


@pytest.mark.asyncio
async def test_middleware_records_caller_identity_not_token(monkeypatch):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from okta_mcp_server.utils import caller

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer", provider.get_tracer)
    token = SimpleNamespace(
        token="raw-access-token",
        client_id="cid",
        subject=None,
        claims={"sub": "jane@example.com", "uid": "00u1abcdEFGHijklMN2o"},
    )
    monkeypatch.setattr(caller, "_access_token", lambda: token)

    mw = telemetry.build_tool_middleware()

    async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
        return _FakeResult(content=[_Block("ok")])

    await mw.on_call_tool(_FakeContext(_FakeMessage("list_users")), call_next)

    (span,) = exporter.get_finished_spans()
    attrs = span.attributes or {}
    assert attrs["enduser.id"] == "00u1abcdEFGHijklMN2o"
    emitted = {str(v) for v in attrs.values()}
    assert "raw-access-token" not in emitted
    assert not any("jane@example.com" in v for v in emitted)
