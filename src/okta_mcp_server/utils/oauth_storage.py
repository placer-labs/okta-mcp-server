# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""Shared OAuth proxy state in Valkey, so more than one replica can serve logins.

FastMCP's default store is an encrypted file tree on local disk. With
OKTA_OAUTH_PROXY_VALKEY_HOST set, client registrations, OAuth transactions and
upstream tokens go to Valkey instead, wrapped in the same Fernet encryption and
key derivation FastMCP applies to its disk store.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from key_value.aio.protocols import AsyncKeyValue

ENV_PREFIX = "OKTA_OAUTH_PROXY_VALKEY_"

# A stalled Valkey fails the OAuth request after this long instead of hanging it.
# redis-py also retries a dropped connection a few times with backoff by default.
TIMEOUT_SECONDS = 5.0


def valkey_connection_kwargs(env: Mapping[str, str] = os.environ) -> dict[str, Any] | None:
    """Redis client arguments from the OKTA_OAUTH_PROXY_VALKEY_* variables.

    Returns None when no host is set, which keeps FastMCP's disk store.
    """
    host = env.get(f"{ENV_PREFIX}HOST", "").strip()
    if not host:
        return None
    kwargs: dict[str, Any] = {
        "host": host,
        "port": int(env.get(f"{ENV_PREFIX}PORT", "6379")),
        "db": int(env.get(f"{ENV_PREFIX}DB", "0")),
        "username": env.get(f"{ENV_PREFIX}USERNAME") or None,
        "password": env.get(f"{ENV_PREFIX}PASSWORD") or None,
        "socket_timeout": TIMEOUT_SECONDS,
        "socket_connect_timeout": TIMEOUT_SECONDS,
        "health_check_interval": 30,
        "decode_responses": True,
    }
    if env.get(f"{ENV_PREFIX}TLS", "").strip().lower() == "true":
        kwargs["ssl"] = True
        if ca_file := env.get(f"{ENV_PREFIX}TLS_CA_FILE"):
            kwargs["ssl_ca_certs"] = ca_file
    return kwargs


def build_valkey_storage(jwt_signing_key: bytes, connection: dict[str, Any]) -> AsyncKeyValue:
    """Encrypted Valkey-backed storage for ``OAuthProxy(client_storage=...)``.

    Pings Valkey once first, so a wrong host, password or TLS setting stops the
    server at startup instead of failing the first login.
    """
    import redis
    import redis.asyncio
    from cryptography.fernet import Fernet
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.redis import RedisStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    probe = redis.Redis(**connection)
    try:
        probe.ping()
    except redis.RedisError as e:
        raise RuntimeError(f"Cannot reach Valkey at {connection['host']}:{connection['port']}: {e}") from e
    finally:
        probe.close()

    # RedisStore talks to Valkey through the pure-Python redis client;
    # valkey-glide ships no musl wheels for the Alpine image.
    return FernetEncryptionWrapper(
        key_value=RedisStore(client=redis.asyncio.Redis(**connection)),
        fernet=Fernet(
            key=derive_jwt_key(
                high_entropy_material=jwt_signing_key.decode(),
                salt="fastmcp-storage-encryption-key",
            )
        ),
        raise_on_decryption_error=False,
    )
