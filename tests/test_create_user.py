# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for create_user's activate parameter (STAGED user support)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.users.users import create_user

PROFILE = {"firstName": "A", "lastName": "B", "email": "a@b.co", "login": "a@b.co"}


def _user():
    user = MagicMock()
    user.id = "00u1"
    user.model_dump.return_value = {"id": "00u1", "status": "STAGED", "profile": PROFILE}
    return user


@pytest.mark.asyncio
@pytest.mark.parametrize("activate", [True, False])
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_activate_is_passed_through(mock_get_client, activate):
    client = AsyncMock()
    client.create_user.return_value = (_user(), None, None)
    mock_get_client.return_value = client

    result = await create_user(profile=PROFILE, activate=activate, ctx=MagicMock(request_context=None))

    assert client.create_user.await_args.args[1] is activate
    assert result[0]["id"] == "00u1"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_activate_defaults_to_true(mock_get_client):
    client = AsyncMock()
    client.create_user.return_value = (_user(), None, None)
    mock_get_client.return_value = client

    await create_user(profile=PROFILE, ctx=MagicMock(request_context=None))

    assert client.create_user.await_args.args[1] is True
