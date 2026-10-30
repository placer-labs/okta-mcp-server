# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.serialization import describe_exception, none_body_error, okta_tool_error
from okta_mcp_server.utils.summarize import summarize_authenticators

_SCOPE = "okta.authenticators.read"


@mcp.tool()
async def list_authenticators(ctx: Context):
    """List the authenticators (MFA factors) configured in the Okta organization.

    Use this to audit which authenticators are active (Okta Verify, phone, email, WebAuthn,
    Duo, etc.) and how they are configured, e.g. whether email/phone are allowed for recovery
    or authentication, and Okta Verify user-verification and compliance settings.

    Returns:
        Dict containing:
        - items: List of authenticators with id, key, name, status, type, created, lastUpdated,
            settings (secret-like keys removed) and provider.type when present. Provider
            configuration (e.g. Duo integration/secret keys) is never returned.
        - total_fetched: Number of authenticators returned.
    """
    logger.info("Listing authenticators")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        authenticators, response, err = await client.list_authenticators()

        if err:
            logger.error(f"Okta API error while listing authenticators: {err}")
            raise okta_tool_error(err, _SCOPE, "listing authenticators")

        if authenticators is None:
            empty = none_body_error("list_authenticators", "listing authenticators", "Call this tool again.")["error"]
            raise okta_tool_error(response, _SCOPE, "listing authenticators", fallback=empty)

        items = summarize_authenticators(list(authenticators))
        logger.info(f"Successfully retrieved {len(items)} authenticator(s)")
        return {"items": items, "total_fetched": len(items)}
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing authenticators: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
