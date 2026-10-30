# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Scope-based tool loading.

``prune_tools_by_scope`` runs once at startup, after the tool modules are
imported, and disables every tool whose required scope (per
``TOOL_SCOPE_REGISTRY``) is not in ``OKTA_SCOPES``, so the LLM never sees tools
the token cannot call. It reads the configured scopes rather than a token, so it
works the same in stdio mode and in HTTP mode, where OAuthProxy only ever
requests the configured scopes.
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable

from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

#: Maps tool_name → required_scope for every tool disabled at startup
_DISABLED_TOOLS: dict[str, str] = {}

#: The okta.* scopes configured at startup
_CONFIGURED_SCOPES: set[str] = set()


def get_disabled_tools() -> dict[str, str]:
    """Return a copy of the tools disabled at startup and the scope each needs."""
    return dict(_DISABLED_TOOLS)


def get_startup_scopes() -> set[str]:
    """Return the okta.* scopes that were configured at startup."""
    return set(_CONFIGURED_SCOPES)


def configured_okta_scopes(raw: str | None = None) -> set[str]:
    """Return the ``okta.*`` scopes from ``raw`` (default: ``OKTA_SCOPES``)."""
    if raw is None:
        raw = os.environ.get("OKTA_SCOPES", "")
    return {s for s in raw.split() if s.startswith("okta.")}


def read_only_mode() -> bool:
    """``OKTA_MCP_READ_ONLY`` disables every write tool regardless of the configured scopes."""
    return os.environ.get("OKTA_MCP_READ_ONLY", "").strip().lower() in ("1", "true", "yes")


def scope_satisfied(required: str, configured: set[str]) -> bool:
    """A ``.manage`` scope also covers the ``.read`` scope for the same resource."""
    if required in configured:
        return True
    if required.endswith(".read"):
        return required.removesuffix(".read") + ".manage" in configured
    return False


def require_scopes(*required_scopes: str, error_return_type: str = "dict") -> Callable:
    """Call-time counterpart of ``prune_tools_by_scope`` for upstream-ported tools.

    Pruning already hides these tools, so this only fires on a direct call. It
    follows the same rules: nothing is enforced when no ``okta.*`` scope is
    configured, and ``.manage`` covers ``.read``. ``error_return_type`` is accepted
    for upstream signature compatibility; failures raise ``ToolError``.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            if read_only_mode() and any(not s.endswith(".read") for s in required_scopes):
                raise ToolError("This server runs in read-only mode (OKTA_MCP_READ_ONLY); write tools are disabled.")
            configured = configured_okta_scopes()
            missing = [s for s in required_scopes if configured and not scope_satisfied(s, configured)]
            if missing:
                raise ToolError(
                    f"Missing OAuth scope(s) {', '.join(missing)}: add them to OKTA_SCOPES, grant them to "
                    "the Okta app, and restart the server."
                )
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


async def prune_tools_by_scope(server: Any, raw_scopes: str | None = None) -> None:
    """Disable tools whose required scope is not configured.

    When no ``okta.*`` scope is configured at all, nothing is pruned: that is a
    misconfiguration that would otherwise hide every tool.
    """
    global _DISABLED_TOOLS, _CONFIGURED_SCOPES
    _DISABLED_TOOLS = {}
    _CONFIGURED_SCOPES = configured_okta_scopes(raw_scopes)
    read_only = read_only_mode()

    if not _CONFIGURED_SCOPES and not read_only:
        logger.warning("[scope-guard] No okta.* scopes in OKTA_SCOPES; leaving all tools enabled")
        return

    registered = {t.name for t in await server.list_tools()}
    unmapped = registered - TOOL_SCOPE_REGISTRY.keys() - {"get_scope_status"}
    if unmapped:
        if read_only:
            # Fail closed: an unmapped tool can't be proven read-only.
            _DISABLED_TOOLS.update(dict.fromkeys(unmapped, "unmapped"))
        else:
            logger.warning(f"[scope-guard] Tools without a scope mapping stay enabled: {sorted(unmapped)}")

    for name in sorted(registered & TOOL_SCOPE_REGISTRY.keys()):
        required = TOOL_SCOPE_REGISTRY[name]
        if read_only and not required.endswith(".read"):
            _DISABLED_TOOLS[name] = required
        elif _CONFIGURED_SCOPES and not scope_satisfied(required, _CONFIGURED_SCOPES):
            _DISABLED_TOOLS[name] = required

    if _DISABLED_TOOLS:
        server.disable(names=set(_DISABLED_TOOLS), components={"tool"})

    logger.info(
        f"[scope-guard] {len(registered) - len(_DISABLED_TOOLS)}/{len(registered)} tools enabled based on "
        f"OKTA_SCOPES; disabled: {sorted(_DISABLED_TOOLS) or 'none'}"
    )
