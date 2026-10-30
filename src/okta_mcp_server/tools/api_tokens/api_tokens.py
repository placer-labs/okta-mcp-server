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
from okta_mcp_server.utils.summarize import summarize_api_tokens

_SCOPE = "okta.apiTokens.read"


@mcp.tool()
async def list_api_tokens(ctx: Context):
    """List metadata for the active Okta API (SSWS) tokens in the organization.

    Use this to audit who owns API tokens, which OAuth client created them, when they expire,
    and whether they are network-restricted. Token values are never returned by Okta or this tool.

    Returns:
        Dict containing:
        - items: List of tokens with id, name, userId (owner), clientName, created, lastUpdated,
            expiresAt, network (connection/include/exclude zones) and tokenWindow when present.
        - total_fetched: Number of tokens returned.
    """
    logger.info("Listing API tokens")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        tokens, response, err = await client.list_api_tokens()

        if err:
            logger.error(f"Okta API error while listing API tokens: {err}")
            raise okta_tool_error(err, _SCOPE, "listing API tokens")

        if tokens is None:
            empty = none_body_error("list_api_tokens", "listing API tokens", "Call this tool again.")["error"]
            raise okta_tool_error(response, _SCOPE, "listing API tokens", fallback=empty)

        items = summarize_api_tokens(list(tokens))
        logger.info(f"Successfully retrieved {len(items)} API token(s)")
        return {"items": items, "total_fetched": len(items)}
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing API tokens: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
