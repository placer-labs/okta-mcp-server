# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""create_user and update_user send exactly the profile keys the caller passed.

Ported from upstream okta/okta-mcp-server#137, extended to create_user and to
custom attributes, which the plain-dict request used to drop.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import CreateUserRequest, UpdateUserRequest

from okta_mcp_server.tools.users.users import _profile_with_only, create_user, update_user

USER_ID = "00uTESTUSER0000001"


def _user():
    user = MagicMock()
    user.id = USER_ID
    user.to_dict.return_value = {"id": USER_ID, "profile": {"title": "Engineer"}}
    return user


class TestProfileWithOnly:
    def test_only_supplied_standard_fields_are_serialized(self):
        assert _profile_with_only({"title": "Engineer", "department": "Eng"}).to_dict() == {
            "title": "Engineer",
            "department": "Eng",
        }

    def test_custom_attributes_are_kept(self):
        assert _profile_with_only({"title": "Engineer", "workgroup": "Platform"}).to_dict() == {
            "title": "Engineer",
            "workgroup": "Platform",
        }

    def test_camel_case_aliases_are_accepted(self):
        assert _profile_with_only({"displayName": "Test User"}).to_dict() == {"displayName": "Test User"}

    def test_explicit_null_still_clears(self):
        assert _profile_with_only({"costCenter": None}).to_dict() == {"costCenter": None}

    def test_sdk_from_dict_nulls_omitted_fields(self):
        """The SDK pitfall the helper avoids."""
        profile = UpdateUserRequest.from_dict({"profile": {"title": "Engineer"}}).to_dict()["profile"]
        assert "firstName" in profile
        assert profile["firstName"] is None


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_update_user_sends_only_the_given_keys(mock_get_client):
    client = AsyncMock()
    client.update_user.return_value = (_user(), None, None)
    mock_get_client.return_value = client

    await update_user(
        user_id=USER_ID, profile={"title": "Engineer", "workgroup": "Platform"}, ctx=MagicMock(request_context=None)
    )

    user_id, body = client.update_user.call_args.args
    assert user_id == USER_ID
    assert isinstance(body, UpdateUserRequest)
    assert body.to_dict() == {"profile": {"title": "Engineer", "workgroup": "Platform"}}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_create_user_keeps_custom_attributes(mock_get_client):
    client = AsyncMock()
    client.create_user.return_value = (_user(), None, None)
    mock_get_client.return_value = client
    profile = {"login": "a@example.com", "email": "a@example.com", "firstName": "A", "lastName": "B", "workgroup": "x"}

    await create_user(profile=profile, ctx=MagicMock(request_context=None))

    body = client.create_user.call_args.args[0]
    assert isinstance(body, CreateUserRequest)
    assert body.to_dict() == {"profile": profile}
