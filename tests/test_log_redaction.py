# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

"""User profile values must not reach the server logs."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.tools.applications.applications import create_application
from okta_mcp_server.tools.users.users import create_user, list_users

EMAIL = "jane.doe@example.com"


@pytest.fixture()
def log_lines():
    lines: list[str] = []
    sink_id = logger.add(lines.append, level="DEBUG", format="{message}")
    yield lines
    logger.remove(sink_id)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_create_user_empty_body_keeps_login_out_of_logs(mock_get_client, ctx_no_elicitation, log_lines):
    client = AsyncMock()
    client.create_user.return_value = (None, MagicMock(), None)
    mock_get_client.return_value = client

    with pytest.raises(ToolError):
        await create_user(
            ctx=ctx_no_elicitation, profile={"login": EMAIL, "email": EMAIL, "firstName": "Jane", "lastName": "Doe"}
        )

    joined = "\n".join(log_lines)
    assert log_lines
    assert EMAIL not in joined
    assert "Jane" not in joined


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_list_users_keeps_search_values_out_of_logs(mock_get_client, ctx_no_elicitation, log_lines):
    client = AsyncMock()
    client.list_users.return_value = ([], MagicMock(), None)
    mock_get_client.return_value = client

    await list_users(ctx=ctx_no_elicitation, search=f'profile.email eq "{EMAIL}"', q="Jane")

    joined = "\n".join(log_lines)
    assert log_lines
    assert EMAIL not in joined
    assert "Jane" not in joined


SECRET = "s3cr3t-client-secret-value"


def test_describe_exception_omits_validation_input():
    from okta.models.open_id_connect_application import OpenIdConnectApplication
    from pydantic import ValidationError

    from okta_mcp_server.utils.serialization import describe_exception

    with pytest.raises(ValidationError) as exc_info:
        OpenIdConnectApplication.from_dict(
            {"signOnMode": "OPENID_CONNECT", "label": "x", "credentials": {"oauthClient": {"client_secret": [SECRET]}}}
        )

    assert SECRET in str(exc_info.value)
    message = describe_exception(exc_info.value)
    assert SECRET not in message
    assert "client_secret: string_type" in message


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_create_application_validation_error_keeps_secret_out(mock_get_client, ctx_no_elicitation, log_lines):
    mock_get_client.return_value = AsyncMock()
    app_config = {
        "signOnMode": "OPENID_CONNECT",
        "label": "x",
        "credentials": {"oauthClient": {"client_secret": [SECRET]}},
    }

    with pytest.raises(ToolError) as exc_info:
        await create_application(ctx=ctx_no_elicitation, app_config=app_config)

    assert SECRET not in str(exc_info.value)
    assert SECRET not in "\n".join(log_lines)
