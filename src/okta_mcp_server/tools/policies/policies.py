# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import asyncio
from typing import Any, Dict, Optional

import okta.models as okta_models
from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    has_next_page,
    paginate_all_results,
)
from okta_mcp_server.utils.serialization import describe_exception, none_body_error
from okta_mcp_server.utils.summarize import (
    _obj_to_dict,
    summarize_policies,
    summarize_policy,
    summarize_policy_rule,
    summarize_policy_rules,
)
from okta_mcp_server.utils.validation import validate_ids

_APP_LOOKUP_CONCURRENCY = 5

_POLICY_RULE_MODEL_MAP: Dict[str, Any] = {
    "SIGN_ON": okta_models.OktaSignOnPolicyRule,
    "PASSWORD": okta_models.PasswordPolicyRule,
    "ACCESS_POLICY": okta_models.AccessPolicyRule,
    "PROFILE_ENROLLMENT": okta_models.ProfileEnrollmentPolicyRule,
    "MFA_ENROLL": okta_models.AuthenticatorEnrollmentPolicyRule,
    "IDP_DISCOVERY": okta_models.IdpDiscoveryPolicyRule,
    "DEVICE_SIGNAL_COLLECTION": okta_models.DeviceSignalCollectionPolicyRule,
    "ENTITY_RISK": okta_models.EntityRiskPolicyRule,
    "POST_AUTH_SESSION": okta_models.PostAuthSessionPolicyRule,
}


def _build_policy_rule_model(rule_data: Dict[str, Any]) -> Any:
    model_cls = _POLICY_RULE_MODEL_MAP.get(str(rule_data.get("type", "")).upper(), okta_models.PolicyRule)
    return model_cls.from_dict(rule_data)


@mcp.tool()
async def list_policies(
    ctx: Context,
    type: str,
    status: Optional[str] = None,
    q: Optional[str] = None,
    limit: Optional[int] = None,
    after: Optional[str] = None,
    fetch_all: bool = False,
):
    """List all the policies from the Okta organization with pagination support.

    Parameters:
        type (str, required): Specifies the type of policy to return. Available policy types are:
            OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, IDP_DISCOVERY, ACCESS_POLICY,
            PROFILE_ENROLLMENT, POST_AUTH_SESSION, ENTITY_RISK
        status (str, optional): Refines the query by the status of the policy - ACTIVE or INACTIVE.
        q (str, optional): A query string to search policies by name.
        limit (int, optional): Number of results to return per page (min 20, max 100). Default: 20.
        after (str, optional): Pagination cursor for the next page of policies.
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
        - items: List of policy dictionaries
        - total_fetched: Number of policies returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing policies from Okta organization")
    logger.debug(
        f"Type: '{type}', Status: '{status}', Q: '{q}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}"
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
        okta_client = await get_okta_client(manager)
        params = build_query_params(type=type, status=status, q=q, after=after)
        page_size = 100 if fetch_all else limit
        if page_size:
            params["limit"] = str(page_size)

        logger.debug("Calling Okta API to list policies")
        policies, response, err = await okta_client.list_policies(**params)

        if err:
            logger.error(f"Error listing policies: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not policies:
            logger.info("No policies found")
            return create_paginated_response([], response, fetch_all)

        if fetch_all and has_next_page(response):
            logger.info(f"fetch_all=True, auto-paginating from initial {len(policies)} policies")
            policies, pagination_info = await paginate_all_results(
                okta_client.list_policies, params, policies, response
            )
            logger.info(
                f"Successfully retrieved {len(policies)} policies across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                summarize_policies([_obj_to_dict(policy) for policy in policies]),
                response,
                fetch_all_used=True,
                pagination_info=pagination_info,
            )

        logger.info(f"Successfully retrieved {len(policies)} policies")
        return create_paginated_response(
            summarize_policies([_obj_to_dict(policy) for policy in policies]), response, fetch_all_used=fetch_all
        )

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception listing policies: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def get_policy(ctx: Context, policy_id: str):
    """Retrieve a specific policy by ID.

    Parameters:
        policy_id (str, required): The ID of the policy to retrieve.

    Returns:
        Dict containing the policy details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.get_policy(policy_id)

        if err:
            logger.error(f"Error getting policy {policy_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if policy is None:
            raise ToolError(
                none_body_error(
                    "get_policy", f"retrieving policy {policy_id!r}", "Verify the ID with list_policies(type=...)."
                )["error"]
            )

        return summarize_policy(_obj_to_dict(policy))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception getting policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def list_policy_apps(ctx: Context, policy_id: str):
    """List the applications an app sign-in (ACCESS_POLICY) policy is applied to.

    Use this to see which apps would accept the factors a policy allows, e.g. which apps use a
    "Password only" or "One factor access" policy.

    Parameters:
        policy_id (str, required): The ID of the policy, as returned by list_policies(type="ACCESS_POLICY").

    Returns:
        Dict containing:
        - items: List of {id, label, status, signOnMode}. Only id is set when the app can't be read
            (okta.apps.read not granted).
        - total_fetched: Number of applications returned.
    """
    logger.info(f"Listing applications mapped to policy {policy_id}")
    manager = _resolve_manager(ctx)
    action = f"listing applications for policy {policy_id}"

    try:
        okta_client = await get_okta_client(manager)
        mappings, _, err = await okta_client.list_policy_mappings(policy_id)

        if err:
            logger.error(f"Error {action}: {err}")
            raise ToolError(f"Okta API error: {err}")

        app_ids = []
        for mapping in mappings or []:
            href = getattr(getattr(getattr(mapping, "links", None), "application", None), "href", None)
            if href:
                app_ids.append(href.rstrip("/").rsplit("/", 1)[-1])

        semaphore = asyncio.Semaphore(_APP_LOOKUP_CONCURRENCY)

        async def _describe(app_id: str) -> Dict[str, Any]:
            entry: Dict[str, Any] = {"id": app_id}
            try:
                async with semaphore:
                    app, _, app_err = await okta_client.get_application(app_id)
            except Exception:
                return entry
            if app_err or app is None:
                return entry
            app_dict = _obj_to_dict(getattr(app, "actual_instance", None) or app)
            for key in ("label", "status", "signOnMode"):
                if app_dict.get(key) is not None:
                    entry[key] = app_dict[key]
            return entry

        items = list(await asyncio.gather(*(_describe(app_id) for app_id in app_ids)))

        logger.info(f"Policy {policy_id} is applied to {len(items)} application(s)")
        return {"items": items, "total_fetched": len(items)}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception {action}: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
async def create_policy(ctx: Context, policy_data: Dict[str, Any]):
    """Create a new policy.

    Parameters:
        policy_data (dict, required): The policy configuration containing:
            - type (str, required): Policy type (OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY, PROFILE_ENROLLMENT,
            POST_AUTH_SESSION, ENTITY_RISK, DEVICE_SIGNAL_COLLECTION)
            - name (str, required): Policy name
            - description (str, optional): Policy description
            - status (str, optional): ACTIVE or INACTIVE (default: ACTIVE)
            - priority (int, optional): Priority of the policy
            - conditions (dict, optional): Policy conditions
            - settings (dict, optional): Policy-specific settings

    Returns:
        Dict containing the created policy details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.create_policy(policy_data)

        if err:
            logger.error(f"Error creating policy: {err}")
            raise ToolError(f"Okta API error: {err}")

        if policy is None:
            raise ToolError(
                none_body_error(
                    "create_policy",
                    f"creating policy {policy_data.get('name', 'N/A')!r}",
                    "Use list_policies(type=...) to confirm and retrieve the new policy.",
                )["error"]
            )

        return summarize_policy(_obj_to_dict(policy))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception creating policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def update_policy(ctx: Context, policy_id: str, policy_data: Dict[str, Any]):
    """Update an existing policy.

    Parameters:
        policy_id (str, required): The ID of the policy to update.
        policy_data (dict, required): The updated policy configuration.

    Returns:
        Dict containing the updated policy details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.replace_policy(policy_id, policy_data)

        if err:
            logger.error(f"Error updating policy {policy_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        if policy is None:
            raise ToolError(
                none_body_error(
                    "update_policy",
                    f"updating policy {policy_id!r}",
                    "Re-fetch with get_policy() to confirm the current state.",
                )["error"]
            )

        return summarize_policy(_obj_to_dict(policy))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception updating policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def delete_policy(ctx: Context, policy_id: str):
    """Delete a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to delete.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.delete_policy(policy_id)

        if err:
            logger.error(f"Error deleting policy {policy_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Policy {policy_id} deleted successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception deleting policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def activate_policy(ctx: Context, policy_id: str):
    """Activate a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to activate.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.activate_policy(policy_id)

        if err:
            logger.error(f"Error activating policy {policy_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Policy {policy_id} activated successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception activating policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def deactivate_policy(ctx: Context, policy_id: str):
    """Deactivate a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to deactivate.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.deactivate_policy(policy_id)

        if err:
            logger.error(f"Error deactivating policy {policy_id}: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Policy {policy_id} deactivated successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception deactivating policy: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def list_policy_rules(ctx: Context, policy_id: str):
    """List all rules for a specific policy.

    Parameters:
        policy_id (str, required): The ID of the policy.

    Returns:
        Dict containing:
            - rules (List[Dict]): List of policy rule dictionaries
            - has_next (bool): Whether there are more results
            - next_page_token (Optional[str]): Token for next page
            - error (str): Error message if the operation fails
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        rules, resp, err = await okta_client.list_policy_rules(policy_id)

        if err:
            logger.error(f"Error listing policy rules: {err}")
            raise ToolError(f"Okta API error: {err}")

        if not rules:
            logger.info("No policy rules found")
            return {"rules": []}

        return {
            "rules": summarize_policy_rules([_obj_to_dict(rule) for rule in rules]),
            "has_next": extract_after_cursor(resp) is not None if resp else False,
            "next_page_token": extract_after_cursor(resp) if resp else None,
        }

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception listing policy rules: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", "rule_id", error_return_type="dict")
async def get_policy_rule(ctx: Context, policy_id: str, rule_id: str):
    """Retrieve a specific policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule.

    Returns:
        Dict containing the policy rule details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.get_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error getting policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        if rule is None:
            raise ToolError(
                none_body_error(
                    "get_policy_rule",
                    f"retrieving rule {rule_id!r} for policy {policy_id!r}",
                    "Verify the IDs with list_policy_rules(policy_id=...).",
                )["error"]
            )

        return summarize_policy_rule(_obj_to_dict(rule))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception getting policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", error_return_type="dict")
async def create_policy_rule(ctx: Context, policy_id: str, rule_data: Dict[str, Any]):
    """Create a new rule for a policy.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_data (dict, required): The rule configuration containing:
            - name (str, required): Rule name
            - priority (int, optional): Priority of the rule
            - status (str, optional): ACTIVE or INACTIVE
            - conditions (dict, optional): Rule conditions
            - actions (dict, optional): Rule actions

    Returns:
        Dict containing the created rule details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.create_policy_rule(policy_id, _build_policy_rule_model(rule_data))

        if err:
            logger.error(f"Error creating policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        if rule is None:
            raise ToolError(
                none_body_error(
                    "create_policy_rule",
                    f"creating rule {rule_data.get('name', 'N/A')!r} for policy {policy_id!r}",
                    "Use list_policy_rules(policy_id=...) to confirm and retrieve the new rule.",
                )["error"]
            )

        return summarize_policy_rule(_obj_to_dict(rule))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception creating policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", "rule_id", error_return_type="dict")
async def update_policy_rule(ctx: Context, policy_id: str, rule_id: str, rule_data: Dict[str, Any]):
    """Update an existing policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to update.
        rule_data (dict, required): The updated rule configuration.

    Returns:
        Dict containing the updated rule details.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.replace_policy_rule(policy_id, rule_id, _build_policy_rule_model(rule_data))

        if err:
            logger.error(f"Error updating policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        if rule is None:
            raise ToolError(
                none_body_error(
                    "update_policy_rule",
                    f"updating rule {rule_id!r} for policy {policy_id!r}",
                    "Re-fetch with get_policy_rule() to confirm the current state.",
                )["error"]
            )

        return summarize_policy_rule(_obj_to_dict(rule))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception updating policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", "rule_id", error_return_type="dict")
async def delete_policy_rule(ctx: Context, policy_id: str, rule_id: str):
    """Delete a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to delete.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.delete_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error deleting policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Rule {rule_id} deleted successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception deleting policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", "rule_id", error_return_type="dict")
async def activate_policy_rule(ctx: Context, policy_id: str, rule_id: str):
    """Activate a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to activate.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.activate_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error activating policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Rule {rule_id} activated successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception activating policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e


@mcp.tool()
@validate_ids("policy_id", "rule_id", error_return_type="dict")
async def deactivate_policy_rule(ctx: Context, policy_id: str, rule_id: str):
    """Deactivate a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to deactivate.

    Returns:
        Dict with success status.
    """
    manager = _resolve_manager(ctx)
    okta_client = await get_okta_client(manager)

    try:
        _, _, err = await okta_client.deactivate_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error deactivating policy rule: {err}")
            raise ToolError(f"Okta API error: {err}")

        return {"success": True, "message": f"Rule {rule_id} deactivated successfully"}

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception deactivating policy rule: {describe_exception(e)}")
        raise ToolError(f"Exception: {describe_exception(e)}") from e
