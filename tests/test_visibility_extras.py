# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for policy-app mappings, network zones, user factors and custom roles."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from okta.models.iam_roles import IamRoles
from okta.models.permissions import Permissions
from okta.models.policy_mapping import PolicyMapping
from okta.models.user_factor import UserFactor

from okta_mcp_server.tools.network_zones.network_zones import list_network_zones
from okta_mcp_server.tools.policies.policies import list_policies, list_policy_apps
from okta_mcp_server.tools.roles.roles import list_custom_roles
from okta_mcp_server.tools.users.users import list_user_factors


def _ctx():
    return MagicMock(request_context=None)


def _http_error(status: int):
    err = MagicMock()
    err.status = status
    err.__str__.return_value = f"HTTP {status}"
    return err


def _no_next_page():
    response = MagicMock()
    response.has_next.return_value = False
    response.headers = {}
    return response


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.policies.policies.get_okta_client")
async def test_list_policies_sends_limit_as_string(mock_get_client):
    client = AsyncMock()
    client.list_policies.return_value = ([], _no_next_page(), None)
    mock_get_client.return_value = client

    await list_policies(_ctx(), type="ACCESS_POLICY", limit=50)
    assert client.list_policies.call_args.kwargs["limit"] == "50"

    await list_policies(_ctx(), type="ACCESS_POLICY", fetch_all=True)
    assert client.list_policies.call_args.kwargs["limit"] == "100"

    await list_policies(_ctx(), type="ACCESS_POLICY")
    assert "limit" not in client.list_policies.call_args.kwargs


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.policies.policies.get_okta_client")
async def test_list_policy_apps_resolves_app_ids_and_labels(mock_get_client):
    mappings = [
        PolicyMapping.from_dict(
            {"id": "rsm1", "_links": {"application": {"href": "https://example.okta.com/api/v1/apps/0oa1"}}}
        ),
        PolicyMapping.from_dict(
            {"id": "rsm2", "_links": {"application": {"href": "https://example.okta.com/api/v1/apps/0oa2"}}}
        ),
        PolicyMapping.from_dict({"id": "rsm3", "_links": {}}),
    ]
    client = AsyncMock()
    client.list_policy_mappings.return_value = (mappings, MagicMock(), None)

    apps = {
        "0oa1": (
            {"label": "argocd", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT", "settings": {"x": 1}},
            None,
            None,
        ),
        "0oa2": (None, None, _http_error(403)),
    }
    client.get_application.side_effect = lambda app_id: apps[app_id]
    mock_get_client.return_value = client

    result = await list_policy_apps(_ctx(), policy_id="rst1")

    assert result["total_fetched"] == 2
    assert result["items"][0] == {"id": "0oa1", "label": "argocd", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT"}
    assert result["items"][1] == {"id": "0oa2"}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client")
async def test_list_network_zones_returns_definitions(mock_get_client):
    zone = {
        "id": "nzo1",
        "name": "VPN gateway",
        "type": "IP",
        "status": "ACTIVE",
        "usage": "POLICY",
        "system": False,
        "gateways": [{"type": "CIDR", "value": "203.0.113.0/24"}],
        "_links": {"self": {"href": "https://example.okta.com/api/v1/zones/nzo1"}},
    }
    client = AsyncMock()
    client.list_network_zones.return_value = ([zone], _no_next_page(), None)
    mock_get_client.return_value = client

    result = await list_network_zones(_ctx())

    item = result["items"][0]
    assert item["gateways"] == [{"type": "CIDR", "value": "203.0.113.0/24"}]
    assert item["usage"] == "POLICY"
    assert "_links" not in item


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.network_zones.network_zones.get_okta_client")
async def test_list_network_zones_403_names_the_scope(mock_get_client):
    client = AsyncMock()
    client.list_network_zones.return_value = (None, MagicMock(), _http_error(403))
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match=r"okta\.networkZones\.read"):
        await list_network_zones(_ctx())


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_list_user_factors_omits_profile(mock_get_client):
    factor = UserFactor.from_dict(
        {
            "id": "mbl1",
            "factorType": "sms",
            "provider": "OKTA",
            "status": "ACTIVE",
            "profile": {"phoneNumber": "+15555550100"},
        }
    )
    client = AsyncMock()
    client.list_factors.return_value = ([factor], MagicMock(), None)
    mock_get_client.return_value = client

    result = await list_user_factors("00u1abcdefghijklmnop", _ctx())

    item = result["items"][0]
    assert item["factorType"] == "sms"
    assert item["status"] == "ACTIVE"
    assert "profile" not in item
    assert "+15555550100" not in str(result)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_list_custom_roles_includes_permissions(mock_get_client):
    roles = IamRoles.from_dict({"roles": [{"id": "cr01", "label": "Token creator", "description": "d"}]})
    perms = Permissions.from_dict({"permissions": [{"label": "okta.apiTokens.manage"}, {"label": "okta.users.read"}]})
    client = AsyncMock()
    client.list_roles.return_value = (roles, _no_next_page(), None)
    client.list_role_permissions.return_value = (perms, MagicMock(), None)
    mock_get_client.return_value = client

    result = await list_custom_roles(_ctx())

    item = result["items"][0]
    assert item["id"] == "cr01"
    assert [p["label"] for p in item["permissions"]] == ["okta.apiTokens.manage", "okta.users.read"]
    client.list_role_permissions.assert_awaited_once_with("cr01")
