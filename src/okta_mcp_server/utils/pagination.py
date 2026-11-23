# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Pagination utilities that delegate to the Okta SDK's built-in helpers.

The SDK ships ``okta.pagination.PaginationHelper`` (cursor extraction) and
``okta.pagination.paginate_all`` (auto-paginating async generator). This
module wraps them in the response-shape and result-dict format the MCP tools
have always used, so call sites don't need to change.

Anything that was previously hand-rolled here (Link-header parsing, retry,
delay, max-page guard) is now provided by the SDK.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from loguru import logger
from okta.pagination import PaginationHelper, paginate_all

# ---------------------------------------------------------------------------
# Cursor / has-more helpers — thin adapters over PaginationHelper.
# ---------------------------------------------------------------------------


def _headers_of(response: Any) -> dict[str, Any]:
    if not response or not hasattr(response, "headers") or not response.headers:
        return {}
    return response.headers


def extract_after_cursor(response: Any) -> str | None:
    """Extract the 'after' pagination cursor from an Okta SDK ApiResponse."""
    return PaginationHelper.extract_next_cursor(_headers_of(response))


def has_next_page(response: Any) -> bool:
    """Return True if the ApiResponse indicates another page is available."""
    return PaginationHelper.has_next_page(_headers_of(response))


# ---------------------------------------------------------------------------
# Auto-pagination — wraps okta.pagination.paginate_all.
# ---------------------------------------------------------------------------


async def paginate_all_results(
    api_fn: Callable[..., Awaitable[tuple[Any, Any, Any]]],
    base_params: dict[str, Any],
    initial_items: list[Any],
    initial_response: Any,
    max_pages: int = 50,
) -> tuple[list[Any], dict[str, Any]]:
    """Auto-paginate through all pages, returning (all_items, pagination_info).

    The first page (``initial_items``) is already fetched by the caller; we
    pick up from its ``after`` cursor and walk the rest with the SDK's
    ``paginate_all``. Returning the same dict shape the MCP tools have always
    consumed (``pages_fetched``, ``total_items``, ``stopped_early``,
    ``stop_reason``).
    """
    all_items: list[Any] = list(initial_items) if initial_items else []
    pages_fetched = 1
    pagination_info: dict[str, Any] = {
        "pages_fetched": 1,
        "total_items": len(all_items),
        "stopped_early": False,
        "stop_reason": None,
    }

    after = extract_after_cursor(initial_response)
    if not after:
        pagination_info["total_items"] = len(all_items)
        return all_items, pagination_info

    # paginate_all yields individual items and walks the cursor for us.
    # max_pages is enforced in the SDK; subtract the page we already have.
    remaining_pages = max(0, max_pages - 1)
    if remaining_pages == 0:
        pagination_info["stopped_early"] = True
        pagination_info["stop_reason"] = f"Reached maximum page limit ({max_pages})"
        return all_items, pagination_info

    page_break_count = 1  # we already consumed page 1
    last_page_size = 0
    items_in_current_page = 0
    # We need to count pages. paginate_all yields items, not pages — track via
    # cursor changes. Easiest reliable count is via the limit param echo, so
    # we approximate by tracking len() growth between SDK-internal yields.
    # Practically, the only consumer of pages_fetched is logging, so we
    # increment on every page-sized chunk.
    page_size = base_params.get("limit") or 200

    try:
        async for item in paginate_all(api_fn, max_pages=remaining_pages, after=after, **base_params):
            all_items.append(item)
            items_in_current_page += 1
            last_page_size += 1
            if items_in_current_page >= page_size:
                page_break_count += 1
                items_in_current_page = 0
        if items_in_current_page > 0:
            page_break_count += 1
        pages_fetched = page_break_count
    except Exception as e:
        logger.error(f"Unexpected error during pagination: {e}")
        pagination_info["stopped_early"] = True
        pagination_info["stop_reason"] = f"Unexpected error: {e}"

    pagination_info["pages_fetched"] = pages_fetched
    pagination_info["total_items"] = len(all_items)
    return all_items, pagination_info


# ---------------------------------------------------------------------------
# MCP-specific shapes — kept here, no SDK equivalent.
# ---------------------------------------------------------------------------


def create_paginated_response(
    items: list[Any], response: Any, fetch_all_used: bool = False, pagination_info: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Create a standardized paginated response dict for MCP tool returns."""
    result: dict[str, Any] = {
        "items": items,
        "total_fetched": len(items),
        "has_more": False,
        "next_cursor": None,
        "fetch_all_used": fetch_all_used,
    }

    if not fetch_all_used and response:
        cursor = extract_after_cursor(response)
        result["has_more"] = cursor is not None
        result["next_cursor"] = cursor

    if pagination_info:
        result["pagination_info"] = pagination_info

    return result


def build_query_params(
    search: str = "",
    filter: str | None = None,
    q: str | None = None,
    after: str | None = None,
    limit: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Build a query-parameter dict for Okta v3 SDK keyword-argument calls."""
    query_params: dict[str, Any] = {}

    if search:
        query_params["search"] = search
    if filter:
        query_params["filter"] = filter
    if q:
        query_params["q"] = q
    if after:
        query_params["after"] = after
    if limit:
        query_params["limit"] = limit

    query_params.update({key: value for key, value in kwargs.items() if value is not None and value != ""})

    return query_params
