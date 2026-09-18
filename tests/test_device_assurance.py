# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for the device assurance policy tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError
from okta.models.device_assurance import DeviceAssurance

from okta_mcp_server.tools.device_assurance.device_assurance import (
    _platform_attributes,
    confirm_delete_device_assurance_policy,
    create_device_assurance_policy,
    delete_device_assurance_policy,
    get_device_assurance_policy,
    list_device_assurance_policies,
    replace_device_assurance_policy,
)

MACOS_POLICY = {
    "name": "macOS baseline",
    "platform": "MACOS",
    "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
    "osVersion": {"minimum": "14.2.1"},
}


def _policy(overrides=None):
    return DeviceAssurance.from_dict({**MACOS_POLICY, "id": "dae1", **(overrides or {})})


def _ctx():
    return MagicMock(request_context=None)


# ---------------------------------------------------------------------------
# Platform attribute matrix — derived from the SDK models, not hand-maintained
# ---------------------------------------------------------------------------


def test_platform_attributes_come_from_the_sdk_models():
    assert _platform_attributes("IOS") == ["jailbreak", "osVersion", "screenLockType"]
    # Android accepts disk encryption and secure hardware too, unlike the docs' desktop-only claim.
    assert "diskEncryptionType" in _platform_attributes("ANDROID")
    assert "secureHardwarePresent" in _platform_attributes("ANDROID")
    # ChromeOS carries no compliance attributes at all in this SDK version.
    assert _platform_attributes("CHROMEOS") == []
    assert _platform_attributes("NOPE") == []


# ---------------------------------------------------------------------------
# Silent-drop guards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_data", "expected"),
    [
        # The wrong disk-encryption shape is accepted by the API and enforces nothing.
        ({"name": "x", "platform": "MACOS", "diskEncryptionType": {"type": "ALL_INTERNAL_VOLUMES"}}, "include"),
        ({"name": "x", "platform": "IOS", "secureHardwarePresent": True}, "not accepted for platform IOS"),
        ({"name": "x", "platform": "MACOS", "diskEncryptionType": {"include": ["FULL"]}}, "ALL_INTERNAL_VOLUMES"),
        ({"name": "x"}, "platform is required"),
        ({"name": "x", "platform": "SYMBIAN"}, "Unknown platform"),
    ],
)
async def test_create_rejects_payloads_the_api_would_ignore(policy_data, expected):
    result = await create_device_assurance_policy(_ctx(), policy_data)

    assert expected in result["error"]


@pytest.mark.asyncio
async def test_create_rejects_os_version_on_a_platform_that_ignores_it():
    result = await create_device_assurance_policy(
        _ctx(), {"name": "x", "platform": "CHROMEOS"}, user_stated_os_version="1.2.3"
    )

    assert "not accepted for platform CHROMEOS" in result["error"]
    assert "no compliance attributes" in result["error"]


@pytest.mark.asyncio
async def test_create_rejects_os_version_inside_policy_data():
    result = await create_device_assurance_policy(_ctx(), {**MACOS_POLICY})

    assert "user_stated_os_version" in result["error"]


@pytest.mark.asyncio
async def test_create_rejects_two_component_os_version():
    result = await create_device_assurance_policy(
        _ctx(), {"name": "x", "platform": "MACOS"}, user_stated_os_version="14.2"
    )

    assert "Incomplete OS version" in result["error"]
    assert "14.2.0" in result["error"]


@pytest.mark.asyncio
async def test_list_rejects_two_component_version_threshold():
    result = await list_device_assurance_policies(ctx=_ctx(), version_threshold="14.2")

    assert "Incomplete OS version" in result["error"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_create_builds_os_version_from_user_stated_value(mock_get_client):
    client = AsyncMock()
    client.create_device_assurance_policy.return_value = (_policy(), None, None)
    mock_get_client.return_value = client

    result = await create_device_assurance_policy(
        _ctx(),
        {"name": "macOS baseline", "platform": "MACOS", "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}},
        user_stated_os_version="14.2.1",
    )

    sent = client.create_device_assurance_policy.await_args.args[0]
    assert sent.to_dict()["osVersion"] == {"minimum": "14.2.1"}
    assert result["osVersion"] == {"minimum": "14.2.1"}


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_list_marks_unconfigured_attributes(mock_get_client):
    client = AsyncMock()
    client.list_device_assurance_policies.return_value = ([_policy()], MagicMock(), None)
    mock_get_client.return_value = client

    result = await list_device_assurance_policies(ctx=_ctx())

    status = result["policies"][0]["securityAttributeStatus"]
    assert status["diskEncryptionType"] == "configured"
    assert status["osVersion"] == "configured"
    # Absent from the policy means the check was never configured, not that devices pass it.
    assert status["screenLockType"] == "not_configured"
    assert status["secureHardwarePresent"] == "not_configured"
    assert "retrieved_at" in result


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_list_none_body_advises_retry(mock_get_client):
    client = AsyncMock()
    client.list_device_assurance_policies.return_value = (None, MagicMock(status_code=200), None)
    mock_get_client.return_value = client

    result = await list_device_assurance_policies(ctx=_ctx())

    assert result["policies"] == []
    assert "Call this tool again" in result["warning"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_list_403_raises_scope_error(mock_get_client):
    client = AsyncMock()
    client.list_device_assurance_policies.return_value = (None, MagicMock(status_code=403), None)
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match=r"okta\.deviceAssurance\.read"):
        await list_device_assurance_policies(ctx=_ctx())


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_get_missing_policy_raises(mock_get_client):
    client = AsyncMock()
    client.get_device_assurance_policy.return_value = (None, None, None)
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match="list_device_assurance_policies"):
        await get_device_assurance_policy(_ctx(), "dae1")


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_get_403_error_raises_scope_error(mock_get_client):
    client = AsyncMock()
    client.get_device_assurance_policy.return_value = (None, None, MagicMock(status=403))
    mock_get_client.return_value = client

    with pytest.raises(ToolError, match=r"okta\.deviceAssurance\.read"):
        await get_device_assurance_policy(_ctx(), "dae1")


# ---------------------------------------------------------------------------
# Replace / delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_replace_returns_before_after_and_implications(mock_get_client):
    client = AsyncMock()
    client.get_device_assurance_policy.return_value = (_policy(), None, None)
    client.replace_device_assurance_policy.return_value = (
        _policy({"osVersion": {"minimum": "15.0.1"}}),
        None,
        None,
    )
    mock_get_client.return_value = client

    result = await replace_device_assurance_policy(
        _ctx(),
        "dae1",
        {"name": "macOS baseline", "platform": "MACOS", "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}},
        user_stated_os_version="15.0.1",
    )

    assert result["before"]["osVersion"] == {"minimum": "14.2.1"}
    assert result["after"]["osVersion"] == {"minimum": "15.0.1"}
    change = next(c for c in result["changes"] if c["attribute"] == "osVersion")
    assert "minimum OS version" in change["implication"]


def test_delete_asks_for_confirmation_first():
    result = delete_device_assurance_policy(_ctx(), "dae1")

    assert result[0]["confirmation_required"] is True
    assert "DELETE" in result[0]["message"]
    assert result[0]["device_assurance_id"] == "dae1"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_confirm_delete_executes(mock_get_client):
    client = AsyncMock()
    client.delete_device_assurance_policy.return_value = (None, None, None)
    mock_get_client.return_value = client

    result = await confirm_delete_device_assurance_policy(_ctx(), "dae1", "DELETE")

    assert "deleted successfully" in result[0]["message"]
    client.delete_device_assurance_policy.assert_awaited_once_with("dae1")


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
async def test_confirm_delete_without_the_word_does_nothing(mock_get_client):
    client = AsyncMock()
    mock_get_client.return_value = client

    result = await confirm_delete_device_assurance_policy(_ctx(), "dae1", "yes")

    assert "Deletion cancelled" in result[0]["error"]
    client.delete_device_assurance_policy.assert_not_awaited()


def test_delete_rejects_invalid_id():
    result = delete_device_assurance_policy(_ctx(), "../../etc/passwd")

    assert "error" in result
