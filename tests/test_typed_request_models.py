# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.

"""create/update application and policy rule send typed SDK models, not plain dicts."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.applications import create_application, update_application
from okta_mcp_server.tools.policies.policies import create_policy_rule, update_policy_rule

APP_CONFIG = {
    "name": "bookmark",
    "label": "Test App",
    "signOnMode": "BOOKMARK",
    "settings": {"app": {"url": "https://example.com", "requestIntegration": False}},
}
RULE_DATA = {"name": "r", "type": "PASSWORD", "actions": {"passwordChange": {"access": "ALLOW"}}}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_create_application_sends_subclass_model(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.create_application.return_value = (MagicMock(), MagicMock(), None)
    mock_get_client.return_value = client

    await create_application(ctx=ctx_no_elicitation, app_config=APP_CONFIG)

    body = client.create_application.await_args.args[0]
    assert isinstance(body, okta_models.BookmarkApplication)
    assert body.to_dict()["settings"]["app"]["url"] == "https://example.com"
    assert body.to_dict()["name"] == "bookmark"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_update_application_sends_subclass_model(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.replace_application.return_value = (MagicMock(), MagicMock(), None)
    mock_get_client.return_value = client

    await update_application(ctx=ctx_no_elicitation, app_id="0oaABCDEfghIJKLmnop1", app_config=APP_CONFIG)

    assert isinstance(client.replace_application.await_args.args[1], okta_models.BookmarkApplication)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.policies.policies.get_okta_client")
async def test_create_policy_rule_keeps_actions(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.create_policy_rule.return_value = (MagicMock(), MagicMock(), None)
    mock_get_client.return_value = client

    await create_policy_rule(ctx=ctx_no_elicitation, policy_id="rstABCDEfghIJKLmnop1", rule_data=RULE_DATA)

    body = client.create_policy_rule.await_args.args[1]
    assert isinstance(body, okta_models.PasswordPolicyRule)
    assert body.to_dict()["actions"]["passwordChange"]["access"] == "ALLOW"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.policies.policies.get_okta_client")
async def test_update_policy_rule_keeps_actions(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.replace_policy_rule.return_value = (MagicMock(), MagicMock(), None)
    mock_get_client.return_value = client

    await update_policy_rule(
        ctx=ctx_no_elicitation, policy_id="rstABCDEfghIJKLmnop1", rule_id="ruleABCDEfghIJKLmnop", rule_data=RULE_DATA
    )

    assert isinstance(client.replace_policy_rule.await_args.args[2], okta_models.PasswordPolicyRule)
