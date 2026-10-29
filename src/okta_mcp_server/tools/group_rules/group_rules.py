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
from okta_mcp_server.utils.serialization import describe_exception
from okta_mcp_server.utils.summarize import summarize_group_rule, summarize_group_rules
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
async def list_group_rules(
    ctx: Context,
    search: str = "",
    status: Optional[str] = None,
    expand: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
):
    """List group rules from the Okta organization with pagination support.
    Group rules define automatic membership rules that assign users to groups based on attribute conditions.

    Parameters:
        search (str, optional): SCIM filter expression for server-side filtering.
            Examples: 'name eq "My Rule"', 'name sw "Auto"', 'status eq "ACTIVE" and name co "eng"'
        status (str, optional): Server-side filter by status. Valid values: "ACTIVE", "INACTIVE", "INVALID".
            Translated to a search expression (e.g. status eq "ACTIVE") and sent to the API.
            Can be combined with search (e.g. status="ACTIVE", search='name sw "Auto"').
        expand (str, optional): Expand related data inline. Use "groupIdToGroupNameMap" to resolve
            group IDs in actions.assignUserToGroups to human-readable names in a single API call.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of rules to return per page (min 20, max 100).

    Examples:
        - First call: list_group_rules()
        - Active rules only: list_group_rules(status="ACTIVE")
        - With group names resolved: list_group_rules(expand="groupIdToGroupNameMap")
        - Name search: list_group_rules(search='name sw "Auto-assign"')
        - Combined: list_group_rules(status="ACTIVE", search='name sw "Auto"', fetch_all=True)
        - Next page: list_group_rules(after="cursor_value")

    Returns:
        Dict containing:
        - items: List of group rule objects
        - total_fetched: Number of rules returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing group rules from Okta organization")
    logger.debug(
        f"Search: '{search}', Status: '{status}', Expand: '{expand}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}"
    )

    # Validate limit parameter range
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    # Translate status into a server-side search expression, combined with any existing search
    effective_search = search
    if status is not None:
        status_expr = f'status eq "{status}"'
        effective_search = f"{search} and {status_expr}" if search else status_expr
        logger.debug(f"Translated status='{status}' to search expression: '{effective_search}'")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(search=effective_search, after=after, limit=limit, expand=expand)

        logger.debug("Calling Okta API to list group rules")
        rules, response, err = await client.list_group_rules(**query_params)

        if err:
            logger.error(f"Okta API error while listing group rules: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not rules:
            logger.info("No group rules found")
            return create_paginated_response([], response, fetch_all)

        if fetch_all and has_next_page(response):
            logger.info(f"fetch_all=True, auto-paginating from initial {len(rules)} group rules")
            all_rules, pagination_info = await paginate_all_results(
                client.list_group_rules, query_params, rules, response
            )

            logger.info(
                f"Successfully retrieved {len(all_rules)} group rules across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                summarize_group_rules(all_rules), response, fetch_all_used=True, pagination_info=pagination_info
            )
        else:
            logger.info(f"Successfully retrieved {len(rules)} group rules")
            return create_paginated_response(summarize_group_rules(rules), response, fetch_all_used=fetch_all)

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing group rules: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("rule_id")
async def get_group_rule(rule_id: str, ctx: Context | None = None, expand: Optional[str] = None):
    """Get a group rule by ID from the Okta organization.

    This tool retrieves a group rule by its ID from the Okta organization.

    Parameters:
        rule_id (str, required): The ID of the group rule to retrieve.
        expand (str, optional): Expand related data inline. Use "groupIdToGroupNameMap" to resolve
            group IDs in actions.assignUserToGroups to human-readable names.

    Returns:
        List containing the group rule details.
    """
    logger.info(f"Getting group rule with ID: {rule_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get group rule {rule_id}")

        query_params = build_query_params(expand=expand) if expand else {}
        rule, _, err = await client.get_group_rule(rule_id, **query_params)

        if err:
            logger.error(f"Okta API error while getting group rule {rule_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully retrieved group rule: {rule_id}")
        return [summarize_group_rule(rule)]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while getting group rule {rule_id}: {type(e).__name__}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
