# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for get_login_failures — the paired FAILURE / DENY log query."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

from okta_mcp_server.tools.system_logs.login_failures import get_login_failures


def _log(event_type: str, result: str):
    log = MagicMock()
    log.model_dump.return_value = {
        "published": "2026-01-01T00:00:00.000Z",
        "eventType": event_type,
        "severity": "WARN",
        "outcome": {"result": result},
    }
    return log


def _response(headers=None):
    resp = MagicMock()
    resp.headers = headers or {}
    return resp


def _client(failure_logs, deny_logs, err=None):
    """Client whose list_log_events answers per outcome filter."""
    client = AsyncMock()

    def list_log_events(**params):
        if err:
            return None, None, err
        logs = failure_logs if 'eq "FAILURE"' in params.get("filter", "") else deny_logs
        return logs, _response(), None

    client.list_log_events.side_effect = list_log_events
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.system_logs.login_failures.get_okta_client")
async def test_queries_both_outcomes_and_categorises(mock_get_client):
    mock_get_client.return_value = _client(
        failure_logs=[_log("user.session.start", "FAILURE"), _log("system.dns.lookup", "FAILURE")],
        deny_logs=[_log("policy.evaluate_sign_on", "DENY")],
    )

    result = await get_login_failures(ctx=MagicMock(request_context=None))

    assert result["failures"]["total"] == 2
    assert len(result["failures"]["login_events"]) == 1
    assert len(result["failures"]["other_events"]) == 1
    assert result["denials"]["total"] == 1
    assert len(result["denials"]["login_events"]) == 1
    assert "1 authentication failure" in result["summary"]
    assert "1 policy denial" in result["summary"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.system_logs.login_failures.get_okta_client")
async def test_defaults_to_last_24_hours(mock_get_client):
    mock_get_client.return_value = _client([], [])

    result = await get_login_failures(ctx=MagicMock(request_context=None))

    assert result["time_window"]["since"] < result["time_window"]["until"]
    assert result["summary"].startswith("No login failures")


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.system_logs.login_failures.get_okta_client")
async def test_user_id_scopes_the_filter(mock_get_client):
    client = _client([], [])
    mock_get_client.return_value = client

    await get_login_failures(ctx=MagicMock(request_context=None), user_id="00u1")

    filters = [call.kwargs["filter"] for call in client.list_log_events.await_args_list]
    assert all('actor.id eq "00u1"' in f for f in filters)
    assert {
        'outcome.result eq "FAILURE" and actor.id eq "00u1"',
        'outcome.result eq "DENY" and actor.id eq "00u1"',
    } == set(filters)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.system_logs.login_failures.get_okta_client")
async def test_scope_error_raises_tool_error(mock_get_client):
    mock_get_client.return_value = _client([], [], err="HTTP 403 insufficient_scope")

    with pytest.raises(ToolError, match=r"okta\.logs\.read"):
        await get_login_failures(ctx=MagicMock(request_context=None))


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.system_logs.login_failures.paginate_all_results")
@patch("okta_mcp_server.tools.system_logs.login_failures.has_next_page")
@patch("okta_mcp_server.tools.system_logs.login_failures.get_okta_client")
async def test_page_limit_surfaces_warning(mock_get_client, mock_has_next, mock_paginate):
    mock_get_client.return_value = _client([_log("user.session.start", "FAILURE")], [])
    mock_has_next.return_value = True
    mock_paginate.return_value = (
        [_log("user.session.start", "FAILURE")],
        {
            "pages_fetched": 50,
            "total_items": 1,
            "stopped_early": True,
            "stop_reason": "Reached maximum page limit (50)",
        },
    )

    result = await get_login_failures(ctx=MagicMock(request_context=None))

    assert any("FAILURE query hit the page limit" in w for w in result["warnings"])
