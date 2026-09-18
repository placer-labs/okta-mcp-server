# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""OpenTelemetry tracing + metrics for the Okta MCP server.

The server previously emitted only loguru JSON logs to Loki, so diagnosing a
failure meant grepping log lines and there was no error-rate signal to alert on.
This module adds OTLP traces and metrics:

* One span per MCP tool call (``mcp.tool/<name>``) with duration and status.
* A counter (``mcp.tool.calls``) and error counter (``mcp.tool.errors``), plus a
  duration histogram (``mcp.tool.duration``), labelled by tool name and status.
* Best-effort spans for outbound Okta HTTP calls (the Okta SDK uses aiohttp).

Everything is **gated on ``OTEL_EXPORTER_OTLP_ENDPOINT``**: if that env var is
unset (local dev, stdio, tests) telemetry is a no-op and no OpenTelemetry code
runs. The deployment turns it on by pointing it at the cluster OTLP collector.

Notably, the tool functions catch their own exceptions and *return* an error
payload (``"Exception: ..."`` / ``"Error: ..."`` / ``{"error": ...}``) rather
than raising, so the middleware inspects the result to detect those swallowed
errors in addition to any exception that propagates.
"""

from __future__ import annotations

import os
import time
from importlib import metadata
from typing import Any

from loguru import logger

_configured = False

# Toggles (env). HTTP tracing = inbound Starlette request spans. Health-probe
# suppression drops /health from BOTH access logs and request traces so k8s
# liveness/readiness noise stays out of Loki/Tempo. Both default on.
HTTP_TRACING_ENV = "OKTA_MCP_HTTP_TRACING"
SUPPRESS_HEALTH_PROBES_ENV = "OKTA_MCP_SUPPRESS_HEALTH_PROBES"


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def telemetry_enabled() -> bool:
    """True when an OTLP endpoint is configured, i.e. telemetry should run."""
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def http_tracing_enabled() -> bool:
    """Whether inbound HTTP (Starlette) request spans are enabled."""
    return _flag(HTTP_TRACING_ENV, True)


def suppress_health_probes() -> bool:
    """Whether /health probe requests are excluded from logs and traces."""
    return _flag(SUPPRESS_HEALTH_PROBES_ENV, True)


def _package_version() -> str:
    try:
        return metadata.version("okta-mcp-server")
    except metadata.PackageNotFoundError:
        return "dev"


def configure_telemetry() -> bool:
    """Configure OTLP trace + metric providers if an endpoint is set.

    Returns ``True`` when telemetry is active, ``False`` when disabled or the
    OpenTelemetry libraries are unavailable. Idempotent.
    """
    global _configured
    if _configured:
        return True
    if not telemetry_enabled():
        logger.debug("telemetry: OTEL_EXPORTER_OTLP_ENDPOINT unset; OpenTelemetry disabled")
        return False

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # pragma: no cover - libs missing
        logger.warning(f"telemetry: OpenTelemetry libraries unavailable, telemetry disabled: {exc}")
        return False

    # Endpoint, headers, and protocol are read from the standard OTEL_* env vars
    # by the exporters; we only set service identity here.
    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "okta-mcp-server"),
            "service.version": _package_version(),
            "deployment.environment": os.environ.get("DEPLOY_ENV", "prod"),
        }
    )

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tracer_provider)

    reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))

    # Outbound Okta API calls go through aiohttp inside the SDK. Best effort:
    # missing optional dep must not disable the core tracing above.
    try:
        from opentelemetry.instrumentation.aiohttp_client import AioHttpClientInstrumentor

        AioHttpClientInstrumentor().instrument()
    except Exception as exc:  # pragma: no cover - optional
        logger.debug(f"telemetry: aiohttp client instrumentation skipped: {exc}")

    # OAuth token and introspection calls to Okta go through httpx (authlib),
    # not aiohttp, so instrument it too — otherwise the auth hot path is
    # untraced. FastMCP 4 moved to httpx2, which needs its own instrumentor;
    # instrument whichever is installed.
    for instrumentor_name in ("HTTPXClientInstrumentor", "HTTPX2ClientInstrumentor"):
        try:
            import opentelemetry.instrumentation.httpx as _otel_httpx

            getattr(_otel_httpx, instrumentor_name)().instrument()
            logger.debug(f"telemetry: {instrumentor_name} instrumented")
        except Exception as exc:  # pragma: no cover - optional
            logger.debug(f"telemetry: {instrumentor_name} skipped: {exc}")

    _install_loguru_trace_correlation()

    # Inbound HTTP request spans. Global instrumentation must run before FastMCP
    # builds its Starlette app inside mcp.run(). /health probe requests are
    # excluded from traces when suppression is on (matches the access-log filter).
    if http_tracing_enabled():
        try:
            from opentelemetry.instrumentation.starlette import StarletteInstrumentor

            if suppress_health_probes():
                os.environ.setdefault("OTEL_PYTHON_STARLETTE_EXCLUDED_URLS", "health")
            StarletteInstrumentor().instrument()
            logger.info("telemetry: inbound HTTP request tracing enabled (Starlette)")
        except Exception as exc:  # pragma: no cover - optional
            logger.debug(f"telemetry: Starlette instrumentation skipped: {exc}")

    _configured = True
    logger.info("telemetry: OpenTelemetry tracing + metrics enabled (OTLP http)")
    return True


def _otel_loguru_patcher(record: Any) -> None:
    """Inject the active trace/span id into each loguru record's ``extra``.

    With ``serialize=True`` these surface in the JSON logs as
    ``extra.trace_id`` / ``extra.span_id``, letting Grafana link a Loki line to
    its Tempo trace (configure a Loki derived field on ``trace_id``). No-op when
    there is no active span.
    """
    from opentelemetry import trace

    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        record["extra"]["trace_id"] = f"{ctx.trace_id:032x}"
        record["extra"]["span_id"] = f"{ctx.span_id:016x}"


def _install_loguru_trace_correlation() -> None:
    """Attach the trace-context patcher to loguru (handlers left untouched)."""
    try:
        from loguru import logger as _loguru

        _loguru.configure(patcher=_otel_loguru_patcher)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"telemetry: loguru trace correlation skipped: {exc}")


def _result_is_error(result: Any) -> bool:
    """Detect a tool result that represents a swallowed error.

    Tools return their errors as content rather than raising, e.g.
    ``["Exception: ..."]``, ``["Error: ..."]`` or ``{"error": ...}``.
    """
    try:
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict) and "error" in structured:
            return True
        for block in getattr(result, "content", None) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str) and text.lstrip().startswith(("Exception:", "Error:")):
                return True
    except Exception:  # pragma: no cover - defensive
        return False
    return False


def build_tool_middleware():
    """Build a FastMCP middleware that records a span + metrics per tool call.

    Imported lazily so this module is import-safe when OpenTelemetry is absent.
    """
    from fastmcp.server.middleware import Middleware
    from opentelemetry import metrics, trace
    from opentelemetry.trace import Status, StatusCode

    tracer = trace.get_tracer("okta_mcp_server")
    meter = metrics.get_meter("okta_mcp_server")
    calls = meter.create_counter("mcp.tool.calls", unit="1", description="MCP tool invocations")
    errors = meter.create_counter(
        "mcp.tool.errors", unit="1", description="MCP tool invocations that failed or returned an error"
    )
    duration = meter.create_histogram("mcp.tool.duration", unit="ms", description="MCP tool call duration")

    class OTelToolMiddleware(Middleware):
        async def on_call_tool(self, context, call_next):
            name = getattr(context.message, "name", "unknown")
            attrs = {"mcp.tool.name": name}
            start = time.perf_counter()
            with tracer.start_as_current_span(f"mcp.tool/{name}", attributes=attrs) as span:
                status = "ok"
                try:
                    result = await call_next(context)
                except Exception as exc:
                    status = "exception"
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                    span.set_attribute("mcp.tool.status", status)
                    errors.add(1, {**attrs, "mcp.tool.status": status})
                    raise
                finally:
                    duration.record((time.perf_counter() - start) * 1000, attrs)
                    calls.add(1, attrs)

                if _result_is_error(result):
                    status = "error"
                    span.set_attribute("mcp.tool.result_error", True)
                    span.set_status(Status(StatusCode.ERROR, "tool returned an error result"))
                    errors.add(1, {**attrs, "mcp.tool.status": status})
                span.set_attribute("mcp.tool.status", status)
                return result

    return OTelToolMiddleware()
