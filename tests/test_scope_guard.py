# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for scope-based tool loading."""

from __future__ import annotations

import importlib

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from okta_mcp_server.utils import scope_guard
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

_TOOL_MODULES = [
    "api_tokens.api_tokens",
    "applications.applications",
    "applications.group_push",
    "authenticators.authenticators",
    "device_assurance.device_assurance",
    "group_rules.group_rules",
    "groups.groups",
    "policies.policies",
    "roles.roles",
    "system_logs.login_failures",
    "system_logs.system_logs",
    "users.users",
]


@pytest.fixture(scope="module")
def server():
    from okta_mcp_server.server import mcp

    for mod in _TOOL_MODULES:
        importlib.import_module(f"okta_mcp_server.tools.{mod}")
    return mcp


def _fake_server(*names: str) -> FastMCP:
    mcp = FastMCP("test")
    for name in names:
        mcp.tool(name=name)(lambda: None)
    return mcp


async def _names(mcp: FastMCP) -> set[str]:
    return {t.name for t in await mcp.list_tools()}


@pytest.mark.asyncio
async def test_every_registered_tool_has_a_scope(server):
    names = await _names(server)
    assert names - TOOL_SCOPE_REGISTRY.keys() == {"get_scope_status"}


def test_manage_scope_covers_read():
    assert scope_guard.scope_satisfied("okta.users.read", {"okta.users.manage"})
    assert not scope_guard.scope_satisfied("okta.users.manage", {"okta.users.read"})
    assert not scope_guard.scope_satisfied("okta.groups.read", {"okta.users.manage"})


@pytest.mark.asyncio
async def test_prunes_tools_missing_their_scope():
    mcp = _fake_server("list_users", "create_user", "list_groups", "get_logs")
    await scope_guard.prune_tools_by_scope(mcp, "openid okta.users.read okta.logs.read")

    assert await _names(mcp) == {"list_users", "get_logs"}
    assert scope_guard.get_disabled_tools() == {
        "create_user": "okta.users.manage",
        "list_groups": "okta.groups.read",
    }
    assert scope_guard.get_startup_scopes() == {"okta.users.read", "okta.logs.read"}


@pytest.mark.asyncio
async def test_no_okta_scopes_leaves_everything_enabled():
    mcp = _fake_server("list_users", "create_user")
    await scope_guard.prune_tools_by_scope(mcp, "openid profile email offline_access")

    assert await _names(mcp) == {"list_users", "create_user"}
    assert scope_guard.get_disabled_tools() == {}


@pytest.mark.asyncio
async def test_unmapped_tools_stay_enabled():
    mcp = _fake_server("list_users", "some_new_tool")
    await scope_guard.prune_tools_by_scope(mcp, "okta.groups.read")

    assert await _names(mcp) == {"some_new_tool"}


@pytest.mark.asyncio
async def test_read_only_mode_disables_write_and_unmapped_tools(monkeypatch):
    monkeypatch.setenv("OKTA_MCP_READ_ONLY", "true")
    mcp = _fake_server("list_users", "create_user", "delete_application", "some_new_tool")
    await scope_guard.prune_tools_by_scope(mcp, "okta.users.manage okta.apps.manage")

    assert await _names(mcp) == {"list_users"}
    assert scope_guard.get_disabled_tools() == {
        "create_user": "okta.users.manage",
        "delete_application": "okta.apps.manage",
        "some_new_tool": "unmapped",
    }


@pytest.mark.asyncio
async def test_read_only_mode_applies_without_okta_scopes(monkeypatch):
    monkeypatch.setenv("OKTA_MCP_READ_ONLY", "1")
    mcp = _fake_server("list_users", "create_user")
    await scope_guard.prune_tools_by_scope(mcp, "openid profile email")

    assert await _names(mcp) == {"list_users"}


@pytest.mark.asyncio
async def test_read_only_mode_rejects_direct_write_calls(monkeypatch):
    monkeypatch.setenv("OKTA_MCP_READ_ONLY", "true")
    monkeypatch.setenv("OKTA_SCOPES", "okta.users.manage")

    @scope_guard.require_scopes("okta.users.manage")
    async def write():  # ruff: ignore[unused-async]
        return "wrote"

    @scope_guard.require_scopes("okta.users.read")
    async def read():  # ruff: ignore[unused-async]
        return "read"

    with pytest.raises(ToolError, match="read-only"):
        await write()
    assert await read() == "read"
