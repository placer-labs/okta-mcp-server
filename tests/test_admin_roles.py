# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for the read-only admin role tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from okta.models.list_group_assigned_roles200_response_inner import ListGroupAssignedRoles200ResponseInner
from okta.models.role_assigned_users import RoleAssignedUsers

from okta_mcp_server.tools.roles.roles import list_admin_role_assignments, list_app_admin_roles
from okta_mcp_server.utils.okta_compat import apply_okta_sdk_leniency

SUPER_ADMIN = {
    "id": "ra1",
    "type": "SUPER_ADMIN",
    "label": "Super Administrator",
    "assignmentType": "USER",
    "status": "ACTIVE",
}
CUSTOM_ROLE = {
    "id": "ra2",
    "type": "CUSTOM",
    "label": "Helpdesk",
    "assignmentType": "CLIENT",
    "status": "ACTIVE",
    "role": "cr0abc",
    "resource-set": "iam0abc",
}


def _deserialize(data, response_type):
    apply_okta_sdk_leniency()
    from okta.api_client import ApiClient

    return ApiClient.__new__(ApiClient).deserialize(json.dumps(data), response_type)


def _ctx():
    return MagicMock(request_context=None)


def _response(headers=None):
    return MagicMock(headers=headers or {})


def _users_page(ids, next_after=None):
    body = {"value": [{"id": i, "orn": f"orn:okta:directory:x:users:{i}"} for i in ids]}
    if next_after:
        body["_links"] = {"next": {"href": f"https://example.okta.com/api/v1/iam/assignees/users?after={next_after}"}}
    return RoleAssignedUsers.from_dict(body)


def _user(login):
    user = MagicMock()
    user.profile.login = login
    return user


def _http_error(status: int):
    err = MagicMock()
    err.status = status
    return err


def _client(pages, roles_by_user, logins=None):
    client = AsyncMock()
    client.list_users_with_role_assignments.side_effect = [(p, _response(), None) for p in pages]

    def roles(user_id):
        value = roles_by_user[user_id]
        if isinstance(value, tuple):
            return value
        return ([ListGroupAssignedRoles200ResponseInner.from_dict(r) for r in value], _response(), None)

    def get_user(user_id):
        if logins is None:
            return (None, _response(), _http_error(403))
        return (_user(logins[user_id]), _response(), None)

    client.list_assigned_roles_for_user.side_effect = roles
    client.get_user.side_effect = get_user
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_lists_users_with_their_roles_across_pages(mock_get_client):
    client = _client(
        [_users_page(["00u1"], next_after="c1"), _users_page(["00u2"])],
        {"00u1": [SUPER_ADMIN], "00u2": [SUPER_ADMIN, {**CUSTOM_ROLE, "assignmentType": "GROUP"}]},
        logins={"00u1": "a@x.co", "00u2": "b@x.co"},
    )
    mock_get_client.return_value = client

    result = await list_admin_role_assignments(_ctx())

    assert result["truncated"] is False
    assert result["total_fetched"] == 2
    first, second = result["items"]
    assert first["userId"] == "00u1"
    assert first["login"] == "a@x.co"
    assert first["roles"][0]["type"] == "SUPER_ADMIN"
    assert first["roles"][0]["label"] == "Super Administrator"
    assert first["roles"][0]["assignmentType"] == "USER"
    assert second["roles"][1]["role"] == "cr0abc"
    assert second["roles"][1]["resource-set"] == "iam0abc"
    assert client.list_users_with_role_assignments.await_args_list[1].kwargs["after"] == "c1"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_caps_users_and_reports_truncation(mock_get_client):
    client = _client(
        [_users_page(["00u1", "00u2"], next_after="c1")],
        {"00u1": [SUPER_ADMIN], "00u2": [SUPER_ADMIN]},
    )
    mock_get_client.return_value = client

    result = await list_admin_role_assignments(_ctx(), max_users=1)

    assert result["truncated"] is True
    assert [i["userId"] for i in result["items"]] == ["00u1"]
    assert "login" not in result["items"][0]
    client.list_users_with_role_assignments.assert_awaited_once()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_per_user_error_is_reported_not_fatal(mock_get_client):
    client = _client(
        [_users_page(["00u1", "00u2"])],
        {"00u1": [SUPER_ADMIN], "00u2": (None, _response(), "rate limited")},
    )
    mock_get_client.return_value = client

    result = await list_admin_role_assignments(_ctx())

    assert result["items"][0]["roles"][0]["type"] == "SUPER_ADMIN"
    assert result["items"][1]["roles"] == []
    assert "rate limited" in result["items"][1]["error"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_list_admin_role_assignments_403_names_the_scope(mock_get_client):
    client = AsyncMock()
    client.list_users_with_role_assignments.return_value = (None, _response(), _http_error(403))
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match=r"okta\.roles\.read"):
        await list_admin_role_assignments(_ctx())


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_list_app_admin_roles_unwraps_one_of(mock_get_client):
    client = AsyncMock()
    # The SDK's strict oneOf rejects every role as matching both schemas; okta_compat resolves it.
    roles = _deserialize(
        [{**SUPER_ADMIN, "assignmentType": "CLIENT"}, CUSTOM_ROLE], "List[ListRolesForClient200ResponseInner]"
    )
    client.list_roles_for_client.return_value = (roles, _response(), None)
    mock_get_client.return_value = client

    result = await list_app_admin_roles(_ctx(), client_id="0oaclient123")

    client.list_roles_for_client.assert_awaited_once_with("0oaclient123")
    assert result["total_fetched"] == 2
    assert result["items"][0] == {
        "id": "ra1",
        "type": "SUPER_ADMIN",
        "label": "Super Administrator",
        "assignmentType": "CLIENT",
        "status": "ACTIVE",
    }
    assert result["items"][1]["resource-set"] == "iam0abc"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.roles.roles.get_okta_client")
async def test_list_app_admin_roles_403_names_the_scope(mock_get_client):
    client = AsyncMock()
    client.list_roles_for_client.return_value = (None, _response(), _http_error(403))
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match=r"okta\.roles\.read"):
        await list_app_admin_roles(_ctx(), client_id="0oaclient123")


@pytest.mark.asyncio
async def test_list_app_admin_roles_rejects_bad_client_id():
    result = await list_app_admin_roles(_ctx(), client_id="../etc")

    assert "error" in result
