# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""OAuth proxy settings in HTTP mode.

server.py builds the OAuthProxy at import time from the environment, so each
case imports it in a fresh interpreter.
"""

from __future__ import annotations

import json
import os
import subprocess  # ruff: ignore[suspicious-subprocess-import] - runs this interpreter on a fixed probe script
import sys

import pytest

_PROBE = """
import json
from okta_mcp_server import server
auth = server.mcp.auth
print(json.dumps({
    "revocation": auth._upstream_revocation_endpoint,
    "registration_ttl": auth._client_registration_ttl_seconds,
    "mask_error_details": server.mcp._mask_error_details,
}))
"""


def _http_config(**env: str) -> dict:
    base = {k: v for k, v in os.environ.items() if not k.startswith(("OKTA_", "FASTMCP_"))}
    base.update(
        MCP_TRANSPORT="streamable-http",
        OKTA_ORG_URL="https://example.okta.com/",
        OKTA_CLIENT_ID="client-id",
        OKTA_CLIENT_SECRET="client-secret-for-tests",
        **env,
    )
    out = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - fixed argv, no shell
        [sys.executable, "-c", _PROBE], env=base, capture_output=True, text=True, check=True, timeout=60
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_defaults():
    assert _http_config() == {
        "revocation": "https://example.okta.com/oauth2/v1/revoke",
        "registration_ttl": 30 * 24 * 3600,
        "mask_error_details": True,
    }


@pytest.mark.parametrize(("value", "expected"), [("3600", 3600), ("0", None)])
def test_registration_ttl_override(value, expected):
    assert _http_config(OKTA_CLIENT_REGISTRATION_TTL=value)["registration_ttl"] == expected


def test_error_details_can_be_unmasked():
    assert _http_config(FASTMCP_MASK_ERROR_DETAILS="false")["mask_error_details"] is False
