# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for the read-only API token and authenticator tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from okta.models.api_token import ApiToken
from okta.models.authenticator_base import AuthenticatorBase

from okta_mcp_server.tools.api_tokens.api_tokens import list_api_tokens
from okta_mcp_server.tools.authenticators.authenticators import list_authenticators
from okta_mcp_server.utils.serialization import to_jsonable
from okta_mcp_server.utils.summarize import summarize_authenticator


def _ctx():
    return MagicMock(request_context=None)


def _client(method: str, result):
    client = AsyncMock()
    getattr(client, method).return_value = result
    return client


def _http_error(status: int):
    err = MagicMock()
    err.status = status
    err.__str__.return_value = f"HTTP {status}"
    return err


TOKEN = {
    "id": "00Tabcd1234",
    "name": "terraform",
    "userId": "00u1",
    "clientName": "Okta API",
    "created": "2026-01-01T00:00:00.000Z",
    "lastUpdated": "2026-01-02T00:00:00.000Z",
    "expiresAt": "2026-02-01T00:00:00.000Z",
    "tokenWindow": "P30D",
    "network": {"connection": "ZONE", "include": ["nzo1"]},
    "_link": {"self": {"href": "https://example.okta.com/api/v1/api-tokens/00Tabcd1234"}},
}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.api_tokens.api_tokens.get_okta_client")
async def test_list_api_tokens_returns_metadata(mock_get_client):
    mock_get_client.return_value = _client("list_api_tokens", ([ApiToken.from_dict(TOKEN)], MagicMock(), None))

    result = await list_api_tokens(_ctx())

    assert result["total_fetched"] == 1
    item = result["items"][0]
    assert item["id"] == "00Tabcd1234"
    assert item["userId"] == "00u1"
    assert item["clientName"] == "Okta API"
    assert item["tokenWindow"] == "P30D"
    assert item["network"]["connection"] == "ZONE"
    assert item["expiresAt"] is not None
    assert "_link" not in item
    assert "link" not in item


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.api_tokens.api_tokens.get_okta_client")
async def test_list_api_tokens_403_names_the_scope(mock_get_client):
    mock_get_client.return_value = _client("list_api_tokens", (None, MagicMock(), _http_error(403)))

    with pytest.raises(ToolError, match=r"okta\.apiTokens\.read"):
        await list_api_tokens(_ctx())


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.api_tokens.api_tokens.get_okta_client")
async def test_list_api_tokens_empty_body(mock_get_client):
    mock_get_client.return_value = _client("list_api_tokens", (None, MagicMock(status=200), None))

    with pytest.raises(ToolError, match="empty response"):
        await list_api_tokens(_ctx())


DUO = {
    "id": "aut1",
    "key": "duo",
    "name": "Duo Security",
    "status": "ACTIVE",
    "type": "app",
    "provider": {
        "type": "DUO",
        "configuration": {
            "host": "api-xxx.duosecurity.com",
            "integrationKey": "DIXXXXXXXXXXXXXXXXXX",
            "secretKey": "duo-secret-key-value",
            "userNameTemplate": {"template": "oktaId"},
        },
    },
}

EMAIL = {
    "id": "aut2",
    "key": "okta_email",
    "name": "Email",
    "status": "ACTIVE",
    "type": "email",
    "settings": {"allowedFor": "recovery", "tokenLifetimeInMinutes": 5},
}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client")
async def test_list_authenticators_keeps_settings_and_drops_provider_secrets(mock_get_client):
    authenticators = [AuthenticatorBase.from_dict(DUO), AuthenticatorBase.from_dict(EMAIL)]
    mock_get_client.return_value = _client("list_authenticators", (authenticators, MagicMock(), None))

    result = await list_authenticators(_ctx())

    assert result["total_fetched"] == 2
    duo, email = result["items"]
    assert duo["key"] == "duo"
    assert duo["provider"] == {"type": "DUO"}
    assert email["settings"]["allowedFor"] == "recovery"
    assert email["settings"]["tokenLifetimeInMinutes"] == 5
    dumped = json.dumps(to_jsonable(result), default=str)
    assert "duo-secret-key-value" not in dumped
    assert "DIXXXXXXXXXXXXXXXXXX" not in dumped
    assert "api-xxx.duosecurity.com" not in dumped


def test_authenticator_settings_scrub_secret_like_keys():
    summary = summarize_authenticator(
        {
            "id": "aut3",
            "key": "custom",
            "settings": {"sharedSecret": "x1", "nested": {"apiKey": "x2", "client_password": "x3"}, "ok": 1},
        }
    )

    assert summary["settings"] == {"nested": {}, "ok": 1}


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client")
async def test_list_authenticators_401_names_the_scope(mock_get_client):
    mock_get_client.return_value = _client("list_authenticators", (None, MagicMock(), _http_error(401)))

    with pytest.raises(ToolError, match=r"okta\.authenticators\.read"):
        await list_authenticators(_ctx())


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.authenticators.authenticators.get_okta_client")
async def test_list_authenticators_other_error(mock_get_client):
    mock_get_client.return_value = _client("list_authenticators", (None, MagicMock(), "boom"))

    with pytest.raises(ToolError, match="Okta API error: boom"):
        await list_authenticators(_ctx())
