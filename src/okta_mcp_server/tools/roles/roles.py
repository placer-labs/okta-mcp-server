# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.pagination import extract_after_cursor
from okta_mcp_server.utils.serialization import describe_exception, none_body_error, okta_tool_error
from okta_mcp_server.utils.summarize import summarize_roles
from okta_mcp_server.utils.validation import validate_ids

_SCOPE = "okta.roles.read"
_PAGE_SIZE = 100
_CONCURRENCY = 5


def _is_auth_error(err: Any) -> bool:
    return (getattr(err, "status", None) or getattr(err, "status_code", None)) in (401, 403, "401", "403")


def _next_cursor(page: Any, response: Any) -> Optional[str]:
    """Cursor from the Link header, falling back to the body's _links.next.href."""
    cursor = extract_after_cursor(response)
    if cursor:
        return cursor
    href = getattr(getattr(getattr(page, "links", None), "next", None), "href", None)
    if not href:
        return None
    return (parse_qs(urlparse(href).query).get("after") or [None])[0]


async def _user_login(client: Any, user_id: str) -> Optional[str]:
    """Best-effort login lookup; needs okta.users.read, so failures just omit it."""
    try:
        user, _, err = await client.get_user(user_id)
    except Exception:
        return None
    if err or user is None:
        return None
    return getattr(getattr(user, "profile", None), "login", None)


@mcp.tool()
async def list_admin_role_assignments(ctx: Context, max_users: int = 200):
    """List every user holding an Okta admin role, with the roles assigned to each.

    Use this to audit who has admin privileges (Super Admin, Org Admin, App Admin, custom roles)
    and whether the role is assigned directly or via a group.

    Parameters:
        max_users (int, optional): Stop after this many users (default 200, max 1000). When the
            org has more, the result is marked truncated.

    Returns:
        Dict containing:
        - items: List of {userId, login, roles: [{id, type, label, assignmentType, status, ...}]}.
            login is omitted when okta.users.read is not granted. A per-user error field is set
            when that user's roles could not be read.
        - total_fetched: Number of users returned.
        - truncated: True if more users with role assignments exist beyond max_users.
    """
    max_users = max(1, min(max_users, 1000))
    logger.info(f"Listing admin role assignments (max_users={max_users})")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        user_ids: List[str] = []
        after: Optional[str] = None
        truncated = False
        while True:
            params: Dict[str, Any] = {"limit": _PAGE_SIZE}
            if after:
                params["after"] = after
            page, response, err = await client.list_users_with_role_assignments(**params)
            if err:
                logger.error(f"Okta API error while listing users with role assignments: {err}")
                raise okta_tool_error(err, _SCOPE, "listing users with role assignments")
            if page is None:
                empty = none_body_error(
                    "list_admin_role_assignments", "listing users with role assignments", "Call this tool again."
                )["error"]
                raise okta_tool_error(response, _SCOPE, "listing users with role assignments", fallback=empty)

            user_ids.extend(uid for u in (page.value or []) if (uid := getattr(u, "id", None)))
            after = _next_cursor(page, response)
            if len(user_ids) >= max_users:
                truncated = len(user_ids) > max_users or after is not None
                user_ids = user_ids[:max_users]
                break
            if not after:
                break

        semaphore = asyncio.Semaphore(_CONCURRENCY)

        async def _one(user_id: str) -> Dict[str, Any]:
            async with semaphore:
                roles, _, role_err = await client.list_assigned_roles_for_user(user_id)
                login = await _user_login(client, user_id)
            entry: Dict[str, Any] = {"userId": user_id}
            if login:
                entry["login"] = login
            if role_err:
                if _is_auth_error(role_err):
                    raise okta_tool_error(role_err, _SCOPE, f"listing roles for user {user_id}")
                entry["error"] = f"Okta API error: {role_err}"
                entry["roles"] = []
            else:
                entry["roles"] = summarize_roles(list(roles or []))
            return entry

        items = await asyncio.gather(*(_one(uid) for uid in user_ids))
        logger.info(f"Retrieved role assignments for {len(items)} user(s) (truncated={truncated})")
        return {"items": list(items), "total_fetched": len(items), "truncated": truncated}
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing admin role assignments: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("client_id", error_return_type="dict")
async def list_app_admin_roles(ctx: Context, client_id: str):
    """List the admin roles assigned to a service (API services) app, identified by its OAuth client_id.

    Use this to audit what Okta admin privileges a machine-to-machine client holds. The client_id
    is the app's credentials.oauthClient.client_id, as returned by get_application.

    Parameters:
        client_id (str, required): The OAuth client_id of the service app.

    Returns:
        Dict containing:
        - items: List of roles with id, type, label, assignmentType, status (plus role and
            resource-set for custom roles).
        - total_fetched: Number of roles returned.
    """
    logger.info(f"Listing admin roles for client {client_id}")
    manager = _resolve_manager(ctx)
    action = f"listing roles for client {client_id}"

    try:
        client = await get_okta_client(manager)
        roles, response, err = await client.list_roles_for_client(client_id)

        if err:
            logger.error(f"Okta API error while {action}: {err}")
            raise okta_tool_error(err, _SCOPE, action)

        if roles is None:
            empty = none_body_error("list_app_admin_roles", action, "Verify the client_id with get_application().")[
                "error"
            ]
            raise okta_tool_error(response, _SCOPE, action, fallback=empty)

        items = summarize_roles(list(roles))
        logger.info(f"Retrieved {len(items)} role(s) for client {client_id}")
        return {"items": items, "total_fetched": len(items)}
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while {action}: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
