# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import Context

import os

import keyring
from loguru import logger
from okta.client import Client as OktaClient

from okta_mcp_server.utils.auth.auth_manager import SERVICE_NAME, OktaAuthManager
from okta_mcp_server.utils.okta_compat import apply_okta_sdk_leniency

# Make the Okta SDK tolerant of live apps that omit fields its generated models
# mark as required (e.g. SAML settings.signOn.*), which would otherwise abort the
# whole list_applications / list_assigned_applications_for_group response.
apply_okta_sdk_leniency()


async def get_okta_client(manager: OktaAuthManager | None) -> OktaClient:
    """Initialize and return an Okta client.

    In stdio mode (manager is not None): uses OktaAuthManager + keyring.
    In HTTP mode (manager is None): gets Okta token from MCP Bearer auth context.
    """
    logger.debug("Initializing Okta client")

    if manager is not None:
        # stdio mode — existing behavior
        if not await manager.is_valid_token():
            logger.warning("Token is invalid or expired, re-authenticating")
            await manager.authenticate()
        # Read after the validity check so a token refreshed inside is_valid_token() is used.
        api_token = keyring.get_password(SERVICE_NAME, "api_token")
        org_url = manager.org_url
    else:
        # HTTP mode — OAuthProxy passes through the upstream Okta access token.
        # The Bearer token in the request IS the Okta access token.
        from mcp.server.auth.middleware.auth_context import get_access_token

        access_token_info = get_access_token()
        if access_token_info is None:
            raise RuntimeError("No authenticated user in HTTP mode")

        api_token = access_token_info.token
        if not api_token:
            raise RuntimeError("No Okta access token in auth context")

        org_url = os.environ.get("OKTA_ORG_URL", "")

    config = {
        "orgUrl": org_url,
        "token": api_token,
        "authorizationMode": "Bearer",
        "userAgent": "okta-mcp-server/0.0.1",
    }
    logger.debug(f"Okta client configured for org: {org_url}")
    return OktaClient(config)


def _resolve_manager(ctx: Context | None) -> OktaAuthManager | None:
    """Safely extract OktaAuthManager from the MCP context.

    Returns None in HTTP mode (where ctx.request_context.lifespan_context
    has no okta_auth_manager) or when ctx itself is None.
    """
    if ctx is None:
        return None
    rc = ctx.request_context
    if rc is None:
        return None
    lc = rc.lifespan_context  # type: ignore[union-attr]
    return getattr(lc, "okta_auth_manager", None)
