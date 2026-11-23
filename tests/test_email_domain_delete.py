# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

"""delete_email_domain still deletes when the name lookup before the prompt fails."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.customization.email_domains.email_domains import delete_email_domain

EMAIL_DOMAIN_ID = "OeD114iNkrcN6aR680g4"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.customization.email_domains.email_domains.get_okta_client")
async def test_delete_after_failed_lookup(mock_get_client, ctx_elicit_accept_true):
    client = AsyncMock()
    client.delete_email_domain.return_value = (None, None, None)
    # The first call (the lookup for the prompt) fails; the delete gets a client.
    mock_get_client.side_effect = [RuntimeError("lookup failed"), client]

    await delete_email_domain(ctx=ctx_elicit_accept_true, email_domain_id=EMAIL_DOMAIN_ID)

    client.delete_email_domain.assert_awaited_once_with(EMAIL_DOMAIN_ID)
