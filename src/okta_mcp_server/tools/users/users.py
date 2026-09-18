# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Optional

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    has_next_page,
    paginate_all_results,
)
from okta_mcp_server.utils.summarize import summarize_groups, summarize_user, summarize_users
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
async def list_users(
    ctx: Context,
    search: str = "",
    filter: Optional[str] = None,
    q: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
):
    """List all the users from the Okta organization with pagination support.
    If search, filter, or q is specified, it will list only those users that satisfy the condition.
    Use after and limit for pagination.
    Use fetch_all=True to automatically fetch all pages of results.
    By default, it will only fetch users whose status is not "DEPROVISIONED".

    Parameters:
        search (str, optional): The value of the search string when searching for some specific set of users.
        filter (str, optional): A filter string to filter users by Okta profile attributes.
        q (str, optional): A query string to search users by Okta profile attributes.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of users to return per page (min 20, max 100).
        The search, filter, and q are performed on user profile attributes.

    Examples:
        To search users whose organization is Okta use search=profile.organization eq "Okta"
        To search users updated after 06/01/2013 but with a status of LOCKED_OUT or RECOVERY use
        search=lastUpdated gt "2013-06-01T00:00:00.000Z" and (status eq "LOCKED_OUT" or status eq "RECOVERY")

        For pagination:
        - First call: list_users(search="profile.department eq \"Engineering\"")
        - Next page: list_users(search="profile.department eq \"Engineering\"", after="cursor_value")
        - All pages: list_users(search="profile.department eq \"Engineering\"", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of (user.profile, user.id) tuples
        - total_fetched: Number of users returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing users from Okta organization")
    logger.debug(
        f"Search: '{search}', Filter: '{filter}', Q: '{q}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}"
    )

    # Validate limit parameter range
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(search=search, filter=filter, q=q, after=after, limit=limit)

        logger.debug("Calling Okta API to list users")
        users, response, err = await client.list_users(**query_params)

        if err:
            logger.error(f"Okta API error while listing users: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not users:
            logger.info("No users found")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        if fetch_all and has_next_page(response):
            logger.info(f"fetch_all=True, auto-paginating from initial {len(users)} users")
            all_users, pagination_info = await paginate_all_results(client.list_users, query_params, users, response)

            logger.info(
                f"Successfully retrieved {len(all_users)} users across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                summarize_users(all_users), response, fetch_all_used=True, pagination_info=pagination_info
            )
        else:
            logger.info(f"Successfully retrieved {len(users)} users")
            return create_paginated_response(summarize_users(users), response, fetch_all_used=fetch_all)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing users: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def get_user_profile_attributes(user_id: Optional[str] = None, ctx: Context | None = None):
    """List the user profile attributes supported by your Okta org.

    Use this to check whether a profile attribute name is valid before filtering or
    searching on it. The prompt may contain an attribute that does not exist, in which
    case list the most similar ones and ask the user which they meant.

    The attribute set is read off one real user, so the values belong to whichever user
    was sampled. To read a specific person's profile, use get_user instead.

    Parameters:
        user_id (str, optional): Read the attributes off this user (ID or login) instead
            of an arbitrary one. Use this when the question is about a named person.

    Returns:
        A dict of user profile attributes.
    """
    logger.info(f"Fetching user profile attributes (user_id={user_id or 'sampled'})")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        if user_id:
            user, _, err = await client.get_user(user_id)
            users = [user] if user else []
        else:
            logger.debug("Fetching first user to extract profile attributes")
            users, _, err = await client.list_users(limit=1)

        if err:
            logger.error(f"Okta API error while fetching profile attributes: {err}")
            raise ToolError(f"Okta API error: {err}")

        if users and len(users) > 0:
            attributes = vars(users[0].profile)
            logger.info(f"Successfully retrieved {len(attributes)} profile attributes")
            logger.debug(f"Profile attributes: {list(attributes.keys())}")
            return attributes

        logger.warning(f"No user found to read profile attributes from (user_id={user_id or 'sampled'})")
        return []
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while fetching profile attributes: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def list_user_groups(
    user_id: str,
    ctx: Context | None = None,
):
    """List all groups that a user belongs to in the Okta organization.

    This tool retrieves all groups for a specific user by their ID from the Okta organization.

    Parameters:
        user_id (str, required): The ID of the user to retrieve groups for.

    Returns:
        List containing the groups the user belongs to.
    """
    logger.info(f"Listing groups for user: {user_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to list groups for user {user_id}")

        groups, _, err = await client.list_user_groups(user_id)

        if err:
            logger.error(f"Okta API error while listing groups for user {user_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not groups:
            logger.info(f"No groups found for user {user_id}")
            return []

        logger.info(f"Successfully retrieved {len(groups)} groups for user {user_id}")
        return summarize_groups(groups)
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing groups for user {user_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def get_user(user_id: str, ctx: Context | None = None):
    """Get a user by ID from the Okta organization

    This tool retrieves a user by their ID from the Okta organization.

    Parameters:
        user_id (str, required): The ID of the user to retrieve.

    Returns:
        List containing the user details.
    """
    logger.info(f"Getting user with ID: {user_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get user {user_id}")

        user, _, err = await client.get_user(user_id)

        if err:
            logger.error(f"Okta API error while getting user {user_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if user is None:
            logger.info(f"User not found: {user_id}")
            return []

        logger.info(f"Successfully retrieved user: {user_id}")
        return [summarize_user(user)]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while getting user {user_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
async def create_user(profile: dict, activate: bool = True, ctx: Context | None = None):
    """Create a user in the Okta organization.

    This tool creates a new user in the Okta organization with the provided profile.

    Parameters:
        profile (dict, required): The profile of the user to create.
        activate (bool, optional): Whether to activate the user on creation. Pass False to
            create the user in STAGED status, which sends no activation email. Default: True.

    Examples:
        - Active user, activation email sent: create_user(profile=user_profile)
        - STAGED user, no email: create_user(profile=user_profile, activate=False)

    Returns:
        List containing the created user details.
    """
    logger.info("Creating new user in Okta organization")
    logger.debug(
        f"User profile: email={profile.get('email', 'N/A')}, login={profile.get('login', 'N/A')}, activate={activate}"
    )

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        # Wrap the profile in a dict with 'profile' key as required by Okta SDK
        user_data = {"profile": profile}
        logger.debug("Calling Okta API to create user")

        user, _, err = await client.create_user(user_data, activate)

        if err:
            logger.error(f"Okta API error while creating user: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully created user: {user.id if user else 'unknown'}")
        return [summarize_user(user)]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while creating user: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def update_user(user_id: str, profile: dict, ctx: Context | None = None):
    """Update a user in the Okta organization.

    This tool updates an existing user in the Okta organization with the provided profile.

    Parameters:
        user_id (str, required): The ID of the user to update.
        profile (dict, required): The updated profile of the user.

    Returns:
        List containing the updated user details.
    """
    logger.info(f"Updating user with ID: {user_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        user_data = {"profile": profile}
        logger.debug(f"Calling Okta API to update user {user_id}")

        user, _, err = await client.update_user(user_id, user_data)

        if err:
            logger.error(f"Okta API error while updating user {user_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully updated user: {user_id}")
        return [summarize_user(user)]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while updating user {user_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def deactivate_user(user_id: str, ctx: Context | None = None):
    """Deactivates a user from the Okta organization.

    This tool deactivates a user from the Okta organization by their ID.
    Deactivating the user is a prerequisite for deleting the user.

    Parameters:
        user_id (str, required): The ID of the user to delete.

    Returns:
        List containing the result of the deactivation operation.
    """
    logger.info(f"Deactivating user with ID: {user_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate user {user_id}")

        _, _, err = await client.deactivate_user(user_id)

        if err:
            logger.error(f"Okta API error while deactivating user {user_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully deactivated user: {user_id}")
        return [f"User {user_id} deactivated successfully."]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while deactivating user {user_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("user_id")
async def delete_deactivated_user(user_id: str, ctx: Context | None = None):
    """Delete a user from the Okta organization who has already been deactivated or deprovisioned.

    This tool deletes a user from the Okta organization by their ID who has already been deactivated or deprovisioned.

    Parameters:
        user_id (str, required): The ID of the deactivated or deprovisioned user to delete.

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Deleting deactivated user with ID: {user_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete user {user_id}")

        _, _, err = await client.delete_user(user_id)

        if err:
            logger.error(f"Okta API error while deleting user {user_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully deleted user: {user_id}")
        return [f"User {user_id} deleted successfully."]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while deleting user {user_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e
