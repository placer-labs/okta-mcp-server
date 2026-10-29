# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import asyncio
import json
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import okta.models as okta_models
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
from okta_mcp_server.utils.serialization import none_body_error
from okta_mcp_server.utils.summarize import summarize_application, summarize_applications
from okta_mcp_server.utils.validation import validate_ids

_SIGN_ON_MODE_MODEL_MAP: Dict[str, Any] = {
    "BOOKMARK": okta_models.BookmarkApplication,
    "AUTO_LOGIN": okta_models.AutoLoginApplication,
    "BASIC_AUTH": okta_models.BasicAuthApplication,
    "BROWSER_PLUGIN": okta_models.BrowserPluginApplication,
    "OPENID_CONNECT": okta_models.OpenIdConnectApplication,
    "SAML_1_1": okta_models.Saml11Application,
    "SAML_2_0": okta_models.SamlApplication,
    "SECURE_PASSWORD_STORE": okta_models.SecurePasswordStoreApplication,
    "WS_FEDERATION": okta_models.WsFederationApplication,
}


def _build_application_model(app_config: Dict[str, Any]) -> Any:
    sign_on_mode = app_config.get("signOnMode") or app_config.get("sign_on_mode", "")
    model_cls = _SIGN_ON_MODE_MODEL_MAP.get(str(sign_on_mode).upper(), okta_models.Application)
    return model_cls.from_dict(app_config)


@mcp.tool()
async def list_applications(
    ctx: Context,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    filter: Optional[str] = None,
    expand: Optional[str] = None,
    include_non_deleted: Optional[bool] = None,
    fetch_all: bool = False,
):
    """List all applications from the Okta organization with pagination support.

    Parameters:
        q (str, optional): Searches for applications by label, property, or link
        after (str, optional): Specifies the pagination cursor for the next page of results
        limit (int, optional): Specifies the number of results per page (min 20, max 100)
        filter (str, optional): Filters applications by status, user.id, group.id, or credentials.signing.kid
        expand (str, optional): Expands the app user object to include the user's profile or expand the app group
        object to include the group's profile
        include_non_deleted (bool, optional): Include non-deleted applications in the results
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.

    Returns:
        Dict containing:
        - items: List of application objects
        - total_fetched: Number of applications returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing applications from Okta organization")
    logger.debug(f"Query parameters: q='{q}', filter='{filter}', limit={limit}")

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
        query_params = {}

        if q:
            query_params["q"] = q
        if after:
            query_params["after"] = after
        if limit:
            query_params["limit"] = limit
        if filter:
            query_params["filter"] = filter
        if expand:
            query_params["expand"] = expand
        if include_non_deleted is not None:
            query_params["includeNonDeleted"] = include_non_deleted

        logger.debug("Calling Okta API to list applications")
        apps, response, err = await client.list_applications(**query_params)

        if err:
            logger.error(f"Okta API error while listing applications: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not apps:
            logger.info("No applications found")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        if fetch_all and has_next_page(response):
            logger.info(f"fetch_all=True, auto-paginating from initial {len(apps)} applications")
            all_apps, pagination_info = await paginate_all_results(
                client.list_applications, query_params, apps, response
            )
            logger.info(
                f"Successfully retrieved {len(all_apps)} applications across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                summarize_applications(all_apps), response, fetch_all_used=True, pagination_info=pagination_info
            )

        logger.info(f"Successfully retrieved {len(apps)} applications")
        return create_paginated_response(summarize_applications(apps), response, fetch_all_used=fetch_all)
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing applications: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_id", error_return_type="dict")
async def get_application(ctx: Context, app_id: str, expand: Optional[str] = None):
    """Get an application by ID from the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to retrieve
        expand (str, optional): Expands the app user object to include the user's profile or expand the
        app group object

    Returns:
        Dictionary containing the application details or error information.
    """
    logger.info(f"Getting application with ID: {app_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        query_params = {}
        if expand:
            query_params["expand"] = expand

        app, _, err = await client.get_application(app_id, **query_params)

        if err:
            logger.error(f"Okta API error while getting application {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if app is None:
            raise ToolError(
                none_body_error(
                    "get_application", f"retrieving application {app_id!r}", "Verify the ID with list_applications()."
                )["error"]
            )

        logger.info(f"Successfully retrieved application: {app_id}")
        return summarize_application(app)
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while getting application {app_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
async def create_application(ctx: Context, app_config: Dict[str, Any], activate: bool = True):
    """Create a new application in the Okta organization.

    Parameters:
        app_config (dict, required): The application configuration including name, label, signOnMode, settings, etc.
        activate (bool, optional): Execute activation lifecycle operation after creation. Defaults to True.

    Returns:
        Dictionary containing the created application details or error information.
    """
    logger.info("Creating new application in Okta organization")
    logger.debug(f"Application label: {app_config.get('label', 'N/A')}, name: {app_config.get('name', 'N/A')}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        query_params = {"activate": activate}

        logger.debug("Calling Okta API to create application")
        app, _, err = await client.create_application(_build_application_model(app_config), **query_params)

        if err:
            logger.error(f"Okta API error while creating application: {err}")
            raise ToolError(f"Okta API error: {err}")

        if app is None:
            raise ToolError(
                none_body_error(
                    "create_application",
                    "creating the application",
                    "Use list_applications() to confirm and retrieve the new application.",
                )["error"]
            )

        logger.info("Successfully created application")
        return summarize_application(app)
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while creating application: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_id", error_return_type="dict")
async def update_application(ctx: Context, app_id: str, app_config: Dict[str, Any]):
    """Update an application by ID in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to update
        app_config (dict, required): The updated application configuration

    Returns:
        Dictionary containing the updated application details or error information.
    """
    logger.info(f"Updating application with ID: {app_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        logger.debug(f"Calling Okta API to update application {app_id}")
        app, _, err = await client.replace_application(app_id, _build_application_model(app_config))

        if err:
            logger.error(f"Okta API error while updating application {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if app is None:
            raise ToolError(
                none_body_error(
                    "update_application",
                    f"updating application {app_id!r}",
                    "Re-fetch with get_application() to confirm the current state.",
                )["error"]
            )

        logger.info(f"Successfully updated application: {app_id}")
        return summarize_application(app)
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while updating application {app_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_id")
def delete_application(ctx: Context, app_id: str):
    """Delete an application by ID from the Okta organization.

    This tool deletes an application by its ID from the Okta organization, but requires confirmation.

    IMPORTANT: After calling this function, you MUST STOP and wait for the human user to type 'DELETE'
    as confirmation. DO NOT automatically call confirm_delete_application afterward.

    Parameters:
        app_id (str, required): The ID of the application to delete

    Returns:
        List containing the result of the deletion operation or a confirmation request.
    """
    logger.warning(f"Deletion requested for application {app_id}, awaiting confirmation")

    return [
        {
            "confirmation_required": True,
            "message": f"To confirm deletion of application {app_id}, please type 'DELETE'",
            "app_id": app_id,
        }
    ]


@mcp.tool()
@validate_ids("app_id")
async def confirm_delete_application(ctx: Context, app_id: str, confirmation: str):
    """Confirm and execute application deletion after receiving confirmation.

    This function MUST ONLY be called after the human user has explicitly typed 'DELETE' as confirmation.
    NEVER call this function automatically after delete_application.

    Parameters:
        app_id (str, required): The ID of the application to delete
        confirmation (str, required): Must be 'DELETE' to confirm deletion

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Processing deletion confirmation for application {app_id}")

    if confirmation != "DELETE":
        logger.warning(f"Application deletion cancelled for {app_id} - incorrect confirmation")
        return ["Error: Deletion cancelled. Confirmation 'DELETE' was not provided correctly."]

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete application {app_id}")

        _, _, err = await client.delete_application(app_id)

        if err:
            logger.error(f"Okta API error while deleting application {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully deleted application: {app_id}")
        return [f"Application {app_id} deleted successfully"]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while deleting application {app_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_id")
async def activate_application(ctx: Context, app_id: str):
    """Activate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to activate

    Returns:
        List containing the result of the activation operation.
    """
    logger.info(f"Activating application: {app_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to activate application {app_id}")

        _, _, err = await client.activate_application(app_id)

        if err:
            logger.error(f"Okta API error while activating application {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully activated application: {app_id}")
        return [f"Application {app_id} activated successfully"]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while activating application {app_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_id")
async def deactivate_application(ctx: Context, app_id: str):
    """Deactivate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to deactivate

    Returns:
        List containing the result of the deactivation operation.
    """
    logger.info(f"Deactivating application: {app_id}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate application {app_id}")

        _, _, err = await client.deactivate_application(app_id)

        if err:
            logger.error(f"Okta API error while deactivating application {app_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        logger.info(f"Successfully deactivated application: {app_id}")
        return [f"Application {app_id} deactivated successfully"]
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while deactivating application {app_id}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


# ---------------------------------------------------------------------------
# OIN catalog & app installation
# ---------------------------------------------------------------------------

#: Server-side default page size for /api/v1/catalog/apps. The catalog
#: endpoint paginates but, unlike the rest of the Okta API, emits no
#: ``Link: rel="next"`` header (verified against a live org) — so a full page
#: is the only "maybe more" signal, and the ``after`` cursor is the last
#: item's catalog ``name``.
_CATALOG_DEFAULT_PAGE_SIZE = 20

#: Safety limits for fetch_all, mirroring paginate_all_results defaults.
_CATALOG_MAX_PAGES = 500
_CATALOG_PAGE_DELAY_SECONDS = 0.1


async def _catalog_request(
    client, method: str, url: str, body: Optional[Dict[str, Any]] = None, keep_empty_params: bool = False
) -> tuple:
    """Issue a raw request for catalog/OIN endpoints the typed SDK can't serve.

    The typed SDK create path strips the catalog ``name`` key and exposes no
    catalog-apps surface at all, so these tools go through the request
    executor directly.

    Args:
        keep_empty_params: Pass True to forward the body verbatim — by default
            the SDK's create_request prunes empty-string/list/dict values from
            the body (``clear_empty_params``).

    Returns:
        Tuple of ``(response, parsed_body, error)`` — the transport response,
        the JSON-decoded body (``None`` when the body is empty), and the SDK
        error (``None`` on success). ``response`` and ``parsed_body`` are
        ``None`` whenever ``error`` is set.
    """
    executor = client.get_request_executor()
    request, err = await executor.create_request(
        method=method, url=url, body=body or {}, headers={}, oauth=False, keep_empty_params=keep_empty_params
    )
    if err:
        return None, None, err
    response, response_body, err = await executor.execute(request)
    if err:
        return None, None, err
    return response, json.loads(response_body) if response_body else None, None


def _catalog_url(params: Dict[str, Any]) -> str:
    query_string = urlencode(params)
    return "/api/v1/catalog/apps" + (f"?{query_string}" if query_string else "")


def _catalog_next_cursor(page: list, exhausted_below: int) -> Optional[str]:
    """Synthesize the ``after`` cursor for the next catalog page.

    A page shorter than ``exhausted_below`` means the catalog is exhausted;
    otherwise there may be more, and the cursor is the last entry's ``name``.
    The threshold is min(requested limit, server default) rather than the
    requested limit itself: the server may silently cap an over-large limit,
    and a page merely shorter than the request is not proof of exhaustion.
    A page that exactly exhausts the catalog therefore yields a phantom
    cursor whose next page is empty — callers must treat an empty page as
    the true end.
    """
    if len(page) < exhausted_below:
        return None
    last = page[-1]
    return last.get("name") if isinstance(last, dict) else None


@mcp.tool()
async def list_catalog_apps(
    ctx: Context,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    fetch_all: bool = False,
) -> dict:
    """Browse the Okta Integration Network (OIN) app catalog.

    Use this to discover an app's ``name`` (the catalog key) to pass to
    install_oin_app. Apps that support outbound provisioning list a provisioning
    capability in their ``features`` (e.g. a SCIM 2.0 test app). A plain custom
    SAML/OIDC app created with create_application cannot do provisioning; you need
    an installed instance of a provisioning-capable catalog app.

    Parameters:
        q (str, optional): Filters the catalog by app name/keyword (e.g. "scim")
        after (str, optional): Pagination cursor — the ``name`` of the last
            entry of the previous page (returned as ``next_cursor``)
        limit (int, optional): Number of catalog entries per page (server
            default: 20)
        fetch_all (bool, optional): If True, automatically fetch all pages of
            results. The unfiltered catalog holds thousands of entries and can
            take hundreds of sequential requests — strongly prefer combining
            this with ``q``. Default: False.

    Examples:
        For pagination:
        - First call: list_catalog_apps(q="scim")
        - Next page: list_catalog_apps(q="scim", after="cursor_value")
        - All pages: list_catalog_apps(q="scim", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of catalog entries (each has ``name``, ``displayName``,
          ``features``, ``signOnModes``)
        - total_fetched: Number of entries returned
        - has_more: Boolean indicating if more results are available. May be
          conservatively True when the final page is exactly full — an empty
          next page then confirms the end.
        - next_cursor: Cursor for the next page (if has_more is True). Also
          set when fetch_all stopped early, as the resume point.
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Browsing OIN catalog (q='{q}', limit={limit}, fetch_all={fetch_all})")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(q=q, after=after, limit=limit)
        page_size = limit if limit else _CATALOG_DEFAULT_PAGE_SIZE
        exhausted_below = min(page_size, _CATALOG_DEFAULT_PAGE_SIZE)

        _, apps, err = await _catalog_request(client, "GET", _catalog_url(query_params))
        if err:
            logger.error(f"Okta API error while browsing catalog: {err}")
            raise ToolError(f"Okta API error: {err}")

        apps = apps or []
        cursor = _catalog_next_cursor(apps, exhausted_below)

        if not fetch_all:
            logger.info(f"Successfully retrieved {len(apps)} OIN catalog entries")
            result = create_paginated_response(apps, None, fetch_all_used=False)
            # The catalog endpoint sends no Link header, so has_more/next_cursor
            # can't come from the transport response like other list_* tools.
            result["has_more"] = cursor is not None
            result["next_cursor"] = cursor
            return result

        all_apps = list(apps)
        # Dedup by catalog name so a misbehaving `after` cursor (ignored,
        # stripped, or inclusive instead of exclusive) can't duplicate entries
        # or loop; names are the catalog's unique keys.
        seen_names = {a["name"] for a in apps if isinstance(a, dict) and a.get("name")}
        pages_fetched = 1
        pagination_info: Dict[str, Any] = {"stopped_early": False, "stop_reason": None}

        while cursor and pages_fetched < _CATALOG_MAX_PAGES:
            await asyncio.sleep(_CATALOG_PAGE_DELAY_SECONDS)
            next_params = dict(query_params)
            next_params["after"] = cursor
            _, page, page_err = await _catalog_request(client, "GET", _catalog_url(next_params))
            if page_err:
                logger.warning(f"Error fetching catalog page {pages_fetched + 1}: {page_err}")
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = f"API error: {page_err}"
                break

            page = page or []
            if not page:
                cursor = None
                break

            fresh = [a for a in page if not (isinstance(a, dict) and a.get("name") in seen_names)]
            if not fresh:
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = "Pagination cursor did not advance"
                break
            seen_names.update(a["name"] for a in fresh if isinstance(a, dict) and a.get("name"))

            all_apps.extend(fresh)
            pages_fetched += 1
            try:
                await ctx.info(f"Fetching catalog apps... {len(all_apps)} fetched so far ({pages_fetched} pages)")
            except Exception:
                pass

            cursor = _catalog_next_cursor(page, exhausted_below)

        if cursor and pages_fetched >= _CATALOG_MAX_PAGES:
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = f"Reached maximum page limit ({_CATALOG_MAX_PAGES})"
            logger.warning(f"Stopped catalog pagination at {_CATALOG_MAX_PAGES} pages limit")

        pagination_info["pages_fetched"] = pages_fetched
        pagination_info["total_items"] = len(all_apps)
        logger.info(f"Successfully retrieved {len(all_apps)} OIN catalog entries across {pages_fetched} pages")
        result = create_paginated_response(all_apps, None, fetch_all_used=True, pagination_info=pagination_info)
        if pagination_info["stopped_early"] and cursor:
            # Partial result — surface the resume point instead of implying
            # the walk completed.
            result["has_more"] = True
            result["next_cursor"] = cursor
        return result
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while browsing OIN catalog: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("app_name", error_return_type="dict")
async def get_catalog_app(ctx: Context, app_name: str) -> dict:
    """Get a single OIN catalog app definition (including its provisioning schema).

    Parameters:
        app_name (str, required): The catalog app key (from list_catalog_apps)

    Returns:
        Dict with the catalog app definition, or error information.
    """
    logger.info(f"Getting OIN catalog app: {app_name}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        _, app, err = await _catalog_request(client, "GET", f"/api/v1/catalog/apps/{app_name}?expand=schema")
        if err:
            logger.error(f"Okta API error while getting catalog app {app_name}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if app is None:
            raise ToolError(
                f"Okta returned an empty response retrieving catalog app {app_name!r}. "
                "Verify the name with list_catalog_apps()."
            )

        logger.info(f"Successfully retrieved OIN catalog app: {app_name}")
        return app
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while getting catalog app {app_name}: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("name", error_return_type="dict")
async def install_oin_app(
    ctx: Context,
    name: str,
    label: str,
    sign_on_mode: str,
    settings: Optional[Dict[str, Any]] = None,
    activate: bool = True,
) -> dict:
    """Install an instance of an OIN catalog app (e.g. a provisioning-capable SCIM app).

    Unlike create_application (which builds custom apps), this preserves the
    catalog ``name`` key. The typed SDK create path strips ``name`` from the
    request body, so a catalog/OIN app can't be installed through create_application;
    this issues the request directly. Provisioning capability is determined by the
    catalog app definition at install time — it cannot be added to a custom app
    afterwards. Discover ``name`` and the allowed ``signOnMode`` values via
    list_catalog_apps / get_catalog_app.

    Parameters:
        name (str, required): The OIN catalog app key (e.g. from list_catalog_apps)
        label (str, required): Display label for the installed instance
        sign_on_mode (str, required): A sign-on mode the catalog app supports
            (e.g. SAML_2_0, OPENID_CONNECT, SECURE_PASSWORD_STORE, BOOKMARK)
        settings (dict, optional): Additional app settings/profile some OIN apps require
        activate (bool, optional): Activate the app on creation. Defaults to True.

    Returns:
        Dict with the installed application, or error information.
    """
    logger.info(f"Installing OIN app '{name}' (label='{label}', signOnMode='{sign_on_mode}')")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        app_body: Dict[str, Any] = {"name": name, "label": label, "signOnMode": sign_on_mode}
        if settings:
            app_body["settings"] = settings

        query_string = urlencode({"activate": "true" if activate else "false"})
        url = f"/api/v1/apps?{query_string}"

        # keep_empty_params: some OIN apps require settings fields whose value
        # is legitimately an empty string; the SDK would otherwise prune them.
        _, app, err = await _catalog_request(client, "POST", url, body=app_body, keep_empty_params=True)
        if err:
            logger.error(f"Okta API error while installing OIN app '{name}': {err}")
            raise ToolError(f"Okta API error: {err}")

        if app is None:
            raise ToolError(
                f"Okta returned an empty response installing OIN app {name!r}. "
                "Verify the result with list_applications()."
            )

        logger.info(f"Successfully installed OIN app '{name}'")
        return app
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while installing OIN app '{name}': {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e
