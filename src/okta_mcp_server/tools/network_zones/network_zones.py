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
from okta_mcp_server.utils.pagination import has_next_page, paginate_all_results
from okta_mcp_server.utils.serialization import describe_exception, none_body_error, okta_tool_error
from okta_mcp_server.utils.summarize import summarize_network_zones

_SCOPE = "okta.networkZones.read"


@mcp.tool()
async def list_network_zones(ctx: Context):
    """List the network zones defined in the Okta organization.

    Use this to see which IP ranges, proxies, countries or ASNs a zone covers, e.g. to check what a
    sign-on policy rule or an API token's network restriction actually allows.

    Returns:
        Dict containing:
        - items: List of zones with id, name, type (IP, DYNAMIC, DYNAMIC_V2), status, usage (POLICY or
            BLOCKLIST), system, gateways/proxies (IP zones) or locations/asns (dynamic zones).
        - total_fetched: Number of zones returned.
    """
    logger.info("Listing network zones")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        zones, response, err = await client.list_network_zones()

        if err:
            logger.error(f"Okta API error while listing network zones: {err}")
            raise okta_tool_error(err, _SCOPE, "listing network zones")

        if zones is None:
            empty = none_body_error("list_network_zones", "listing network zones", "Call this tool again.")["error"]
            raise okta_tool_error(response, _SCOPE, "listing network zones", fallback=empty)

        zones = list(zones)
        if has_next_page(response):
            zones, _ = await paginate_all_results(client.list_network_zones, {}, zones, response)

        items = summarize_network_zones(zones)
        logger.info(f"Successfully retrieved {len(items)} network zone(s)")
        return {"items": items, "total_fetched": len(items)}
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing network zones: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
