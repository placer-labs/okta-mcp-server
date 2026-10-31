# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for list_group_apps / list_policies pagination support."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.groups.groups import list_group_apps
from okta_mcp_server.tools.policies.policies import list_policies


def _fake_app(app_id: str):
    app = MagicMock()
    app.model_dump.return_value = {"id": app_id, "name": "oidc_client", "label": app_id, "status": "ACTIVE"}
    return app


def _response(after: str | None = None):
    resp = MagicMock()
    resp.headers = {"link": f'<https://x.okta.com/api/v1/x?after={after}>; rel="next"'} if after else {}
    return resp


_CTX = MagicMock(request_context=None)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_list_group_apps_passes_cursor_and_reports_next_page(mock_get_client):
    client = AsyncMock()
    client.list_assigned_applications_for_group.return_value = ([_fake_app("0oa1")], _response("c2"), None)
    mock_get_client.return_value = client

    result = await list_group_apps("00g1", ctx=_CTX, after="c1", limit=50)

    client.list_assigned_applications_for_group.assert_awaited_once_with("00g1", after="c1", limit=50)
    assert result["items"][0]["id"] == "0oa1"
    assert result["has_more"] is True
    assert result["next_cursor"] == "c2"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.paginate_all_results")
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_list_group_apps_fetch_all_walks_pages(mock_get_client, mock_paginate):
    client = AsyncMock()
    client.list_assigned_applications_for_group.return_value = ([_fake_app("0oa1")], _response("c2"), None)
    mock_get_client.return_value = client
    mock_paginate.return_value = ([_fake_app("0oa1"), _fake_app("0oa2")], {"pages_fetched": 2})

    result = await list_group_apps("00g1", ctx=_CTX, fetch_all=True)

    client.list_assigned_applications_for_group.assert_awaited_once_with("00g1", limit=200)
    assert result["fetch_all_used"] is True
    assert {i["id"] for i in result["items"]} == {"0oa1", "0oa2"}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.policies.policies.get_okta_client")
async def test_list_policies_forwards_q_and_limit(mock_get_client):
    client = AsyncMock()
    client.list_policies.return_value = ([], _response(), None)
    mock_get_client.return_value = client

    result = await list_policies(_CTX, type="PASSWORD", q="default", limit=50)

    client.list_policies.assert_awaited_once_with(type="PASSWORD", q="default", limit="50")
    assert result["items"] == []
