# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for caller identity, per-caller rate limiting and caller-tagged logs."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.middleware.rate_limiting import RateLimitError
from loguru import logger
from mcp.shared.exceptions import MCPError

from okta_mcp_server.utils import caller

JANE = "00u1abcdEFGHijklMN2o"
JOHN = "00u9zyxwVUTSrqpoNM8l"


def _token(sub: str | None = None, client_id: str = "cid", uid: str | None = None) -> SimpleNamespace:
    claims = {k: v for k, v in {"sub": sub, "uid": uid}.items() if v}
    return SimpleNamespace(token="raw-access-token", client_id=client_id, subject=sub, claims=claims)


@pytest.fixture
def as_user(monkeypatch):
    current: dict = {"token": None}
    monkeypatch.setattr(caller, "_access_token", lambda: current["token"])

    def _set(sub: str | None, client_id: str = "cid", uid: str | None = None) -> None:
        current["token"] = _token(sub, client_id, uid)

    return _set


def test_identity_and_key(as_user):
    assert caller.caller_identity() is None
    assert caller.rate_limit_key() == "local"
    as_user(None, client_id="app-1")
    assert caller.rate_limit_key() == "client:app-1"
    as_user("jane@example.com", uid=JANE)
    assert caller.caller_identity() == JANE
    assert caller.rate_limit_key() == f"user:{JANE}"
    as_user(JOHN)
    assert caller.caller_identity() == JOHN


def test_email_subject_is_never_emitted(as_user):
    as_user("jane@example.com")
    assert caller.caller_identity() is None
    key = caller.rate_limit_key()
    assert key.startswith("user:")
    assert "jane" not in key
    assert "example.com" not in key


def test_loggable_user_id_hashes_logins():
    assert caller.loggable_user_id(JANE) == JANE
    assert caller.loggable_user_id(None) is None
    hashed = caller.loggable_user_id("jane@example.com")
    assert hashed is not None
    assert hashed.startswith("login:") and "jane" not in hashed
    assert hashed == caller.loggable_user_id("jane@example.com")
    assert (
        caller.scrub_user_id("not found: jane@example.com (User)", "jane@example.com") == f"not found: {hashed} (User)"
    )
    assert caller.scrub_user_id("not found: x", JANE) == "not found: x"
    assert caller.scrub_user_id("users/Jane%40Example.com and JANE@EXAMPLE.COM", "jane@example.com") == (
        f"users/{hashed} and {hashed}"
    )


def test_rate_limit_on_by_default_and_explicit_off():
    default = caller.build_rate_limit_middleware({})
    assert default is not None
    assert default.max_requests_per_second == caller.DEFAULT_RATE_LIMIT_RPS
    assert default.burst_capacity == caller.DEFAULT_RATE_LIMIT_BURST
    assert caller.build_rate_limit_middleware({caller.RATE_LIMIT_RPS_ENV: "0"}) is None


@pytest.mark.asyncio
async def test_rate_limit_is_per_caller(as_user):
    limiter = caller.build_rate_limit_middleware(
        {caller.RATE_LIMIT_RPS_ENV: "0.001", caller.RATE_LIMIT_BURST_ENV: "2"}
    )
    assert limiter is not None
    on_request: Any = limiter.on_request

    async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
        return "ok"

    as_user("jane@example.com", uid=JANE)
    assert await on_request(None, call_next) == "ok"
    assert await on_request(None, call_next) == "ok"
    with pytest.raises(RateLimitError, match="user:00u1abcdEFGHijklMN2o"):
        await on_request(None, call_next)

    as_user("john@example.com", uid=JOHN)
    assert await on_request(None, call_next) == "ok"


@pytest.mark.asyncio
async def test_rate_limit_rejects_tool_calls_end_to_end(as_user):
    mcp = FastMCP("test")

    @mcp.tool()
    def ping() -> str:
        return "pong"

    limiter = caller.build_rate_limit_middleware(
        {caller.RATE_LIMIT_RPS_ENV: "0.001", caller.RATE_LIMIT_BURST_ENV: "5"}
    )
    assert limiter is not None
    mcp.add_middleware(limiter)
    as_user("jane@example.com")
    async with Client(mcp) as client:
        with pytest.raises(MCPError, match="Rate limit exceeded"):
            for _ in range(10):
                await client.call_tool("ping")


@pytest.mark.asyncio
async def test_logs_carry_caller_identity(as_user):
    records: list = []
    sink = logger.add(lambda m: records.append(m.record), level="INFO")
    try:
        as_user("jane@example.com", uid=JANE)

        async def call_next(_ctx):  # ruff: ignore[unused-async] - middleware awaits this callable
            logger.info("inside tool")
            return "ok"

        assert await caller.CallerContextMiddleware().on_request(None, call_next) == "ok"
    finally:
        logger.remove(sink)

    (record,) = [r for r in records if r["message"] == "inside tool"]
    assert record["extra"]["enduser_id"] == JANE
    assert "raw-access-token" not in str(record["extra"])
    assert "jane@example.com" not in str(record["extra"])
