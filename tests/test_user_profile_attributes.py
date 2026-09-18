# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for get_user_profile_attributes.

Prod logs show callers passing user_id, which the tool used to reject.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class _Profile:
    def __init__(self, **attributes):
        self.__dict__.update(attributes)


class TestGetUserProfileAttributes:
    """Callers pass user_id (10 rejected calls in prod on 2026-08-27)."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_user_id_reads_that_user(self, mock_get_client):
        from okta_mcp_server.tools.users.users import get_user_profile_attributes

        user = MagicMock()
        user.profile = _Profile(email="a@b.co")
        client = AsyncMock()
        client.get_user.return_value = (user, None, None)
        mock_get_client.return_value = client

        await get_user_profile_attributes(user_id="a@b.co", ctx=MagicMock(request_context=None))

        client.get_user.assert_awaited_once_with("a@b.co")
        client.list_users.assert_not_awaited()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_without_user_id_samples_one(self, mock_get_client):
        from okta_mcp_server.tools.users.users import get_user_profile_attributes

        user = MagicMock()
        user.profile = _Profile(email="a@b.co")
        client = AsyncMock()
        client.list_users.return_value = ([user], None, None)
        mock_get_client.return_value = client

        await get_user_profile_attributes(ctx=MagicMock(request_context=None))

        client.list_users.assert_awaited_once_with(limit=1)
        client.get_user.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_invalid_user_id_rejected(self):
        from okta_mcp_server.tools.users.users import get_user_profile_attributes

        result = await get_user_profile_attributes(user_id="../../etc/passwd")

        assert "Error" in result[0]
