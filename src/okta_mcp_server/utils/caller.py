# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Caller identity for per-user rate limiting, logs and traces.

Logs and spans only ever carry the Okta user ID (``00u...``), never the login,
email or name. The token itself is never returned or logged.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from loguru import logger

RATE_LIMIT_RPS_ENV = "OKTA_MCP_RATE_LIMIT_RPS"
RATE_LIMIT_BURST_ENV = "OKTA_MCP_RATE_LIMIT_BURST"
DEFAULT_RATE_LIMIT_RPS = 10.0
DEFAULT_RATE_LIMIT_BURST = 20

_OKTA_USER_ID = re.compile(r"00u[0-9A-Za-z]{17}")


def _access_token() -> Any:
    try:
        from fastmcp.server.dependencies import get_access_token

        return get_access_token()
    except Exception:
        return None


def _claims(token: Any) -> dict[str, Any]:
    return getattr(token, "claims", None) or {}


def caller_identity() -> str | None:
    """Return the caller's Okta user ID (``uid``, or ``sub`` if it is one), else ``None``."""
    token = _access_token()
    if token is None:
        return None
    claims = _claims(token)
    for candidate in (claims.get("uid"), claims.get("sub"), getattr(token, "subject", None)):
        if isinstance(candidate, str) and _OKTA_USER_ID.fullmatch(candidate):
            return candidate
    return None


def loggable_user_id(user_id: str | None) -> str | None:
    """Return ``user_id`` if it is an Okta user ID, else a hash, so logins never reach the logs."""
    if user_id is None or _OKTA_USER_ID.fullmatch(user_id):
        return user_id
    return "login:" + hashlib.sha256(user_id.encode()).hexdigest()[:16]


def scrub_user_id(text: object, user_id: str | None) -> str:
    """Return ``text`` with a login-style ``user_id`` replaced by :func:`loggable_user_id`."""
    text = str(text)
    safe = loggable_user_id(user_id)
    return text if not user_id or safe == user_id else text.replace(user_id, safe)


def rate_limit_key(_context: MiddlewareContext | None = None) -> str:
    """Rate-limit bucket key: the caller, else the OAuth client, else one shared local bucket.

    The key appears in rate-limit error messages, so a non-ID subject is hashed.
    """
    user_id = caller_identity()
    if user_id:
        return f"user:{user_id}"
    token = _access_token()
    subject = _claims(token).get("sub") or getattr(token, "subject", None)
    if subject:
        return "user:" + hashlib.sha256(str(subject).encode()).hexdigest()[:16]
    client_id = getattr(token, "client_id", None)
    if client_id:
        return f"client:{client_id}"
    return "local"


class CallerContextMiddleware(Middleware):
    """Bind the caller identity to every log record emitted while a request is handled."""

    async def on_request(self, context, call_next):
        caller = caller_identity()
        if caller is None:
            return await call_next(context)
        with logger.contextualize(enduser_id=caller):
            return await call_next(context)


def build_rate_limit_middleware(environ: dict[str, str] | None = None) -> RateLimitingMiddleware | None:
    """Per-caller token-bucket limiter; on by default, ``OKTA_MCP_RATE_LIMIT_RPS=0`` turns it off."""
    env = os.environ if environ is None else environ
    rps = float(env.get(RATE_LIMIT_RPS_ENV) or DEFAULT_RATE_LIMIT_RPS)
    burst = int(env.get(RATE_LIMIT_BURST_ENV) or DEFAULT_RATE_LIMIT_BURST)
    if rps <= 0:
        logger.warning(f"Rate limiting disabled ({RATE_LIMIT_RPS_ENV}={rps})")
        return None
    logger.info(f"Rate limiting MCP requests per caller: {rps} req/s, burst {burst}")
    return RateLimitingMiddleware(
        max_requests_per_second=rps, burst_capacity=max(burst, 1), get_client_id=rate_limit_key
    )
