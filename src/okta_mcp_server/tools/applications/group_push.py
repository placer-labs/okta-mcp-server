# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, List, Optional

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client


def _summarize_mapping(m: Any) -> Dict[str, Any]:
    """Flatten a GroupPushMapping to the fields worth reading.

    The target group's *name* is not a field on the mapping — only its id — so the
    `_links.targetGroup` href is carried through as the way to resolve it.
    """

    def g(obj: Any, *names: str) -> Any:
        for n in names:
            v = getattr(obj, n, None)
            if v is not None:
                return v
        return None

    links = g(m, "links", "_links")
    target_link = g(links, "target_group", "targetGroup") if links else None

    return {
        "id": g(m, "id"),
        "status": g(m, "status"),
        "source_group_id": g(m, "source_group_id", "sourceGroupId"),
        "target_group_id": g(m, "target_group_id", "targetGroupId"),
        "target_group_href": g(target_link, "href") if target_link else None,
        "last_push": str(g(m, "last_push", "lastPush") or ""),
        "error_summary": g(m, "error_summary", "errorSummary"),
    }


@mcp.tool()
async def list_group_push_mappings(
    ctx: Context,
    app_id: str,
    source_group_id: Optional[str] = None,
    status: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
):
    """List the group push mappings on an application.

    A push mapping is what makes an Okta group appear as a group in the downstream app —
    for a Google/G Suite app, it is the only authoritative statement of which Google group
    an Okta group feeds. The Okta group name does not imply the downstream name, and
    matching the two by membership is unreliable because unrelated groups can have
    identical members.

    Deleting an Okta group that has a push mapping tears down the group it pushes to, so
    check here before retiring one.

    Parameters:
        app_id (str, required): The application ID, e.g. the G Suite app
        source_group_id (str, optional): Only mappings whose source is this Okta group
        status (str, optional): Filter by mapping status, e.g. ACTIVE, INACTIVE, ERROR
        after (str, optional): Pagination cursor for the next page
        limit (int, optional): Results per page (1-1000)

    Returns:
        Dictionary with the mappings, each carrying source_group_id, target_group_id and
        status. The target group's name is not part of the mapping; resolve it from
        target_group_href.
    """
    logger.info(f"Listing group push mappings for app: {app_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        kwargs: Dict[str, Any] = {}
        if source_group_id:
            kwargs["source_group_id"] = source_group_id
        if status:
            kwargs["status"] = status
        if after:
            kwargs["after"] = after
        if limit:
            kwargs["limit"] = limit

        mappings, _, err = await client.list_group_push_mappings(app_id, **kwargs)

        if err:
            logger.error(f"Okta API error listing group push mappings for {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        items: List[Dict[str, Any]] = [_summarize_mapping(m) for m in (mappings or [])]
        logger.info(f"Retrieved {len(items)} group push mappings for app {app_id}")
        return {"app_id": app_id, "mappings": items, "count": len(items)}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Error listing group push mappings for app {app_id}: {e}")
        raise ToolError(f"Error listing group push mappings: {e}") from e
