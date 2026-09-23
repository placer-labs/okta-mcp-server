# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import logging as _stdlib_logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal, Optional, cast

from fastmcp import FastMCP
from loguru import logger

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

LOG_FILE = os.environ.get("OKTA_LOG_FILE")
MCP_TRANSPORT = os.environ.get("MCP_TRANSPORT", "stdio")


class _HealthProbeAccessFilter(_stdlib_logging.Filter):
    """Drop uvicorn access-log lines for /health probe requests.

    K8s liveness/readiness hit /health every few seconds (~24x/min), which
    uvicorn's access logger would otherwise emit as noise to stdout/Loki. Real
    request access logs are kept.
    """

    def filter(self, record: _stdlib_logging.LogRecord) -> bool:
        try:
            return "/health" not in record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True


def _resolve_version() -> str:
    """Version reported by ``/health``.

    Prefer ``APP_VERSION`` (set by the deployment to the image tag) so ``/health``
    reflects the *running build*, not the static package version baked into the
    wheel. Fall back to the installed package metadata, then ``"dev"``.
    """
    env_version = os.environ.get("APP_VERSION")
    if env_version:
        return env_version
    from importlib import metadata

    try:
        return metadata.version("okta-mcp-server")
    except metadata.PackageNotFoundError:
        return "dev"


@dataclass
class OktaAppContext:
    okta_auth_manager: OktaAuthManager | None = None


@asynccontextmanager
async def okta_authorisation_flow(server: FastMCP) -> AsyncIterator[OktaAppContext]:
    """
    Manages the application lifecycle. In stdio mode, initializes OktaAuthManager
    for device/JWT flow. In HTTP mode with OAuthProxy, authentication is handled
    via browser redirect — no OktaAuthManager needed.
    """
    if MCP_TRANSPORT == "streamable-http":
        logger.info("HTTP transport: OAuthProxy handles authentication via browser redirect")
        yield OktaAppContext()
    else:
        logger.info("Initializing OktaAuthManager (authentication deferred to first tool call)")
        manager = OktaAuthManager()
        try:
            yield OktaAppContext(okta_auth_manager=manager)
        finally:
            logger.debug("Clearing Okta tokens")
            manager.clear_tokens()


# --- Build the FastMCP instance based on transport mode ---

if MCP_TRANSPORT == "streamable-http":
    from fastmcp.server.auth import OAuthProxy
    from fastmcp.server.auth.providers.introspection import IntrospectionTokenVerifier

    _mcp_server_url = os.environ.get("MCP_SERVER_URL", "http://localhost:8000")
    _okta_org_url = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    _okta_client_id = os.environ.get("OKTA_CLIENT_ID", "")
    _okta_client_secret = os.environ.get("OKTA_CLIENT_SECRET", "")
    _okta_scopes = os.environ.get("OKTA_SCOPES", "openid profile email offline_access")
    # Cache introspection results to avoid hitting Okta on every tool call.
    # Tune via OKTA_TOKEN_CACHE_TTL (seconds). Default: 60s balances revocation
    # freshness with reduced load. Set to 0 to disable caching.
    _token_cache_ttl = int(os.environ.get("OKTA_TOKEN_CACHE_TTL", "60")) or None
    # Deterministically derive the JWT signing key so issued tokens survive
    # pod restarts. Without this, FastMCP generates a fresh random key at every
    # boot and every previously-issued access/refresh token becomes
    # unverifiable — every connected client has to re-authenticate.
    #
    # Source priority:
    #   1. OKTA_JWT_SIGNING_KEY env var (operator-provided, low-entropy OK)
    #   2. OKTA_CLIENT_SECRET env var (already required by OAuthProxy,
    #      high-entropy by definition)
    # Both are HKDF-stretched with the same salt FastMCP expects. The same
    # input always produces the same key, so no operator key-management is
    # required as long as OKTA_CLIENT_SECRET stays stable.
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key as _derive_jwt_key

    _override_signing_key = os.environ.get("OKTA_JWT_SIGNING_KEY")
    if _override_signing_key:
        _jwt_signing_key: Optional[bytes] = _derive_jwt_key(
            low_entropy_material=_override_signing_key,
            salt="fastmcp-jwt-signing-key",
        )
        logger.info("Derived JWT signing key from OKTA_JWT_SIGNING_KEY override")
    elif _okta_client_secret:
        _jwt_signing_key = _derive_jwt_key(
            high_entropy_material=_okta_client_secret,
            salt="fastmcp-jwt-signing-key",
        )
        logger.info("Derived JWT signing key from OKTA_CLIENT_SECRET")
    else:
        _jwt_signing_key = None
        logger.warning(
            "Neither OKTA_JWT_SIGNING_KEY nor OKTA_CLIENT_SECRET is set; FastMCP "
            "will generate a random signing key per boot and all issued tokens "
            "will be invalidated on pod restart."
        )
    # Authorization consent screen guards against confused-deputy attacks where
    # a third-party site triggers the OAuth flow on behalf of a logged-in user.
    # Default ON (matches FastMCP). Set REQUIRE_AUTHORIZATION_CONSENT=false only
    # for local development.
    _require_consent_raw = os.environ.get("REQUIRE_AUTHORIZATION_CONSENT", "true").lower()
    _require_consent: bool | str = "external" if _require_consent_raw == "external" else _require_consent_raw == "true"

    _auth = OAuthProxy(
        upstream_authorization_endpoint=f"{_okta_org_url}/oauth2/v1/authorize",
        upstream_token_endpoint=f"{_okta_org_url}/oauth2/v1/token",
        upstream_client_id=_okta_client_id,
        upstream_client_secret=_okta_client_secret,
        token_verifier=IntrospectionTokenVerifier(
            introspection_url=f"{_okta_org_url}/oauth2/v1/introspect",
            client_id=_okta_client_id,
            client_secret=_okta_client_secret,
            cache_ttl_seconds=_token_cache_ttl,
        ),
        base_url=_mcp_server_url,
        require_authorization_consent=_require_consent,
        extra_authorize_params={"scope": _okta_scopes},
        jwt_signing_key=_jwt_signing_key,
        # Without this, OAuthProxy derives its default scope from
        # token_verifier.required_scopes — None for introspection — so CIMD and DCR
        # clients (e.g. Claude Code) register with no scopes and hit invalid_scope on
        # authorize. Also advertises the set on the /.well-known metadata endpoints.
        valid_scopes=_okta_scopes.split(),
    )

    mcp = FastMCP(
        "Okta IDaaS MCP Server",
        lifespan=okta_authorisation_flow,
        auth=_auth,
    )
else:
    mcp = FastMCP(
        "Okta IDaaS MCP Server",
        lifespan=okta_authorisation_flow,
    )


# --- Health endpoint (HTTP transport only) ---------------------------------
# Exposed at both `/` and `/health`. Returns JSON suitable for K8s liveness /
# readiness probes and for the existing blackbox-exporter Probe CR — pick
# either path. Always public, never authenticated.

if MCP_TRANSPORT == "streamable-http":
    from starlette.requests import Request as _Request
    from starlette.responses import JSONResponse as _JSONResponse

    _PACKAGE_VERSION = _resolve_version()

    @mcp.custom_route("/", methods=["GET"])
    @mcp.custom_route("/health", methods=["GET"])
    async def _health_check(request: _Request) -> _JSONResponse:  # ruff: ignore[unused-async] - Starlette requires async handlers
        return _JSONResponse(
            {
                "status": "healthy",
                "service": "okta-mcp-server",
                "version": _PACKAGE_VERSION,
                "transport": MCP_TRANSPORT,
            }
        )


def main():
    """Run the Okta MCP server."""
    logger.remove()

    # Silence httpx / httpcore INFO-level logs. They emit full request URLs,
    # which include OAuth bearer tokens in query strings (e.g.
    # `?access_token=...`) for some Okta endpoints — leaving them at INFO
    # leaks credentials into stdout / log aggregators.
    _stdlib_logging.getLogger("httpx").setLevel(_stdlib_logging.WARNING)
    _stdlib_logging.getLogger("httpcore").setLevel(_stdlib_logging.WARNING)

    # Drop /health probe access-log spam (liveness/readiness hit it every few
    # seconds). Keeps access logs for real requests. Toggle off with
    # OKTA_MCP_SUPPRESS_HEALTH_PROBES=false to restore full probe access logging.
    from okta_mcp_server.utils.telemetry import suppress_health_probes

    if suppress_health_probes():
        _stdlib_logging.getLogger("uvicorn.access").addFilter(_HealthProbeAccessFilter())

    if LOG_FILE:
        logger.add(
            LOG_FILE,
            mode="w",
            level=os.environ.get("OKTA_LOG_LEVEL", "INFO"),
            retention="5 days",
            enqueue=True,
            serialize=True,
        )

    logger.add(
        sys.stderr, level=os.environ.get("OKTA_LOG_LEVEL", "INFO"), format="{time} {level} {message}", serialize=True
    )

    logger.info("Starting Okta MCP Server")

    # OpenTelemetry traces + metrics. No-op unless OTEL_EXPORTER_OTLP_ENDPOINT is
    # set, so local/stdio runs are unaffected; the deployment points it at the
    # cluster OTLP collector to activate per-tool spans and error-rate metrics.
    from okta_mcp_server.utils.telemetry import build_tool_middleware, configure_telemetry

    if configure_telemetry():
        mcp.add_middleware(build_tool_middleware())
        logger.info("OpenTelemetry tool-call middleware registered")

    from okta_mcp_server.tools.applications import (
        applications,  # ruff: ignore[unused-import]
        group_push,  # ruff: ignore[unused-import]
    )
    from okta_mcp_server.tools.device_assurance import device_assurance  # ruff: ignore[unused-import]
    from okta_mcp_server.tools.group_rules import group_rules  # ruff: ignore[unused-import]
    from okta_mcp_server.tools.groups import groups  # ruff: ignore[unused-import]
    from okta_mcp_server.tools.policies import policies  # ruff: ignore[unused-import]
    from okta_mcp_server.tools.system_logs import (
        login_failures,  # ruff: ignore[unused-import]
        system_logs,  # ruff: ignore[unused-import]
    )
    from okta_mcp_server.tools.users import users  # ruff: ignore[unused-import]

    if MCP_TRANSPORT == "streamable-http":
        mcp.run(transport=MCP_TRANSPORT, host="0.0.0.0", port=8000)
    else:
        mcp.run(transport=cast(Literal["stdio", "sse", "streamable-http"], MCP_TRANSPORT))
