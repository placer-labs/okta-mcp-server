# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""Valkey storage for the OAuth proxy: settings, startup check, encryption."""

from __future__ import annotations

import fakeredis
import pytest

from okta_mcp_server.utils.oauth_storage import TIMEOUT_SECONDS, build_valkey_storage, valkey_connection_kwargs

KEY = b"0123456789abcdef0123456789abcdef"


def test_no_host_keeps_the_disk_store():
    assert valkey_connection_kwargs({}) is None
    assert valkey_connection_kwargs({"OKTA_OAUTH_PROXY_VALKEY_HOST": "  "}) is None


def test_defaults_bound_every_call():
    kwargs = valkey_connection_kwargs({"OKTA_OAUTH_PROXY_VALKEY_HOST": "valkey"})
    assert kwargs == {
        "host": "valkey",
        "port": 6379,
        "db": 0,
        "username": None,
        "password": None,
        "socket_timeout": TIMEOUT_SECONDS,
        "socket_connect_timeout": TIMEOUT_SECONDS,
        "health_check_interval": 30,
        "decode_responses": True,
    }


def test_acl_user_and_tls():
    kwargs = valkey_connection_kwargs(
        {
            "OKTA_OAUTH_PROXY_VALKEY_HOST": "valkey.internal",
            "OKTA_OAUTH_PROXY_VALKEY_PORT": "6380",
            "OKTA_OAUTH_PROXY_VALKEY_DB": "2",
            "OKTA_OAUTH_PROXY_VALKEY_USERNAME": "okta-mcp",
            "OKTA_OAUTH_PROXY_VALKEY_PASSWORD": "pw",
            "OKTA_OAUTH_PROXY_VALKEY_TLS": "true",
            "OKTA_OAUTH_PROXY_VALKEY_TLS_CA_FILE": "/etc/ssl/valkey-ca.pem",
        }
    )
    assert kwargs is not None
    assert (kwargs["port"], kwargs["db"], kwargs["username"], kwargs["password"]) == (6380, 2, "okta-mcp", "pw")
    assert kwargs["ssl"] is True
    assert kwargs["ssl_ca_certs"] == "/etc/ssl/valkey-ca.pem"


def test_unreachable_valkey_stops_startup():
    kwargs = valkey_connection_kwargs(
        {"OKTA_OAUTH_PROXY_VALKEY_HOST": "127.0.0.1", "OKTA_OAUTH_PROXY_VALKEY_PORT": "1"}
    )
    assert kwargs is not None
    with pytest.raises(RuntimeError, match=r"Cannot reach Valkey at 127\.0\.0\.1:1"):
        build_valkey_storage(KEY, kwargs)


@pytest.mark.asyncio
async def test_values_round_trip_encrypted(monkeypatch):
    server = fakeredis.FakeServer()

    def fake(cls):
        # fakeredis mis-answers redis-py's periodic health-check PING; Valkey doesn't.
        return lambda **kw: cls(server=server, **{k: v for k, v in kw.items() if k != "health_check_interval"})

    monkeypatch.setattr("redis.Redis", fake(fakeredis.FakeRedis))
    monkeypatch.setattr("redis.asyncio.Redis", fake(fakeredis.FakeAsyncRedis))
    kwargs = valkey_connection_kwargs({"OKTA_OAUTH_PROXY_VALKEY_HOST": "valkey"})
    assert kwargs is not None

    storage = build_valkey_storage(KEY, kwargs)
    await storage.put(key="c1", value={"redirect_uri": "http://localhost:33418/cb"}, collection="clients", ttl=60)

    assert await storage.get(key="c1", collection="clients") == {"redirect_uri": "http://localhost:33418/cb"}
    raw = fakeredis.FakeRedis(server=server, decode_responses=True)
    (stored_key,) = raw.keys("*")
    stored = raw.get(stored_key)
    assert isinstance(stored, str)
    assert "33418" not in stored
    assert 0 < raw.ttl(stored_key) <= 60
