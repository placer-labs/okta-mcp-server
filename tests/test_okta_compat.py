# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the Okta SDK leniency shim (okta_compat).

These reproduce the two field-validation failures that abort a whole
``list_applications`` / ``list_assigned_applications_for_group`` response when a
single app violates the SDK's strict generated models:

1. SAML apps missing required ``settings.signOn.*`` fields.
2. Browser-plugin apps whose ``name`` is outside the SDK's hard-coded enum.
"""

from __future__ import annotations

import json

import pytest

from okta_mcp_server.utils.okta_compat import apply_okta_sdk_leniency
from okta_mcp_server.utils.summarize import summarize_applications

# A healthy app the SDK parses without help.
_GOOD_APP = {
    "id": "0oagood",
    "name": "oidc_client",
    "label": "Healthy App",
    "status": "ACTIVE",
    "signOnMode": "AUTO_LOGIN",
    "created": "2020-01-01T00:00:00.000Z",
    "lastUpdated": "2021-01-01T00:00:00.000Z",
}

# SAML app missing the fields the SDK marks required on settings.signOn.
_BAD_SAML_APP = {
    "id": "0oasaml",
    "name": "saml_app",
    "label": "SAML App",
    "status": "ACTIVE",
    "signOnMode": "SAML_2_0",
    "settings": {"signOn": {"defaultRelayState": ""}},
}

# Browser-plugin app with a name outside the SDK's template enum and no app fields.
_BAD_BROWSER_PLUGIN_APP = {
    "id": "0oabp",
    "name": "hellosign_hellofax",
    "label": "HelloSign",
    "status": "ACTIVE",
    "signOnMode": "BROWSER_PLUGIN",
    "settings": {"app": {}},
}


@pytest.fixture()
def deserializer():
    """An ApiClient instance with the leniency patch applied.

    ``ApiClient.__init__`` requires a full Configuration, but ``deserialize`` and
    the patched ``__deserialize_model`` do not touch instance state, so we build
    the instance without running ``__init__``.
    """
    apply_okta_sdk_leniency()
    from okta.api_client import ApiClient

    return ApiClient.__new__(ApiClient)


def _deserialize_app_list(client, apps):
    return client.deserialize(json.dumps(apps), "List[Application]")


def test_strict_browser_plugin_app_aborts_without_patch():
    """Sanity check: without the shim the browser-plugin app raises ValidationError.

    okta 3.4.6 relaxed the SAML ``settings.signOn`` fields, but the browser-plugin
    ``name`` enum is still strict, so the shim is still needed.
    """
    from okta.models.application import Application

    with pytest.raises(Exception) as exc_info:
        Application.from_dict(_BAD_BROWSER_PLUGIN_APP)
    assert "BrowserPluginApplication" in str(exc_info.value)


def test_bad_saml_app_survives_deserialization(deserializer):
    result = _deserialize_app_list(deserializer, [_GOOD_APP, _BAD_SAML_APP])

    assert len(result) == 2
    assert type(result[0]).__name__ == "AutoLoginApplication"
    # The offending app comes back as its correct concrete type, not dropped.
    assert type(result[1]).__name__ == "SamlApplication"
    assert result[1].id == "0oasaml"


def test_bad_browser_plugin_app_survives_deserialization(deserializer):
    result = _deserialize_app_list(deserializer, [_GOOD_APP, _BAD_BROWSER_PLUGIN_APP])

    assert len(result) == 2
    assert type(result[1]).__name__ == "BrowserPluginApplication"
    assert result[1].id == "0oabp"


def test_full_list_summarizes_cleanly(deserializer):
    """The end-to-end path the MCP tools use: deserialize then summarize."""
    result = _deserialize_app_list(deserializer, [_GOOD_APP, _BAD_SAML_APP, _BAD_BROWSER_PLUGIN_APP])
    summaries = summarize_applications(result)

    assert len(summaries) == 3
    ids = {s["id"] for s in summaries}
    assert ids == {"0oagood", "0oasaml", "0oabp"}
    # No exception raised and every app retained its identity fields.
    for summary in summaries:
        assert summary["id"]
        assert summary["name"]


def test_patch_is_idempotent():
    """Calling apply twice must not double-wrap the deserializer."""
    apply_okta_sdk_leniency()
    from okta.api_client import ApiClient

    first = ApiClient._ApiClient__deserialize_model
    apply_okta_sdk_leniency()
    second = ApiClient._ApiClient__deserialize_model
    assert first is second


_STANDARD_ROLE = {"id": "ra1", "type": "SUPER_ADMIN", "label": "Super Administrator", "assignmentType": "CLIENT"}
_CUSTOM_ROLE = {"id": "ra2", "type": "CUSTOM", "label": "Helpdesk", "role": "cr0", "resource-set": "iam0"}


def test_ambiguous_one_of_roles_resolve_to_a_concrete_schema(deserializer):
    roles = deserializer.deserialize(
        json.dumps([_STANDARD_ROLE, _CUSTOM_ROLE]), "List[ListRolesForClient200ResponseInner]"
    )

    standard, custom = (r.actual_instance for r in roles)
    assert type(standard).__name__ == "StandardRole"
    assert standard.label == "Super Administrator"
    assert type(custom).__name__ == "CustomRole"
    assert custom.resource_set == "iam0"
