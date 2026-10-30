# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Tests for the allowlisted get_application detail summary."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import OpenIdConnectApplication, SamlApplication

from okta_mcp_server.tools.applications.applications import get_application, list_applications
from okta_mcp_server.utils.serialization import to_jsonable
from okta_mcp_server.utils.summarize import summarize_application_detail

CLIENT_SECRET = "s3cr3t-client-secret-value"
APP_SETTING_SECRET = "oin-app-setting-secret"

OIDC_APP = {
    "id": "0oa1",
    "name": "oidc_client",
    "label": "Web",
    "status": "ACTIVE",
    "signOnMode": "OPENID_CONNECT",
    "visibility": {"autoLaunch": False, "autoSubmitToolbar": False, "hide": {"iOS": True, "web": False}},
    "credentials": {
        "oauthClient": {
            "client_id": "0oaclient123",
            "client_secret": CLIENT_SECRET,
            "token_endpoint_auth_method": "client_secret_basic",
            "pkce_required": False,
            "autoKeyRotation": True,
        },
        "signing": {"kid": "kid1", "rotationMode": "AUTO"},
    },
    "settings": {
        "app": {"apiToken": APP_SETTING_SECRET},
        "notes": {"admin": "owner: pe", "enduser": "hello"},
        "oauthClient": {
            "redirect_uris": ["https://app.example.com/cb"],
            "post_logout_redirect_uris": ["https://app.example.com/"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "application_type": "web",
            "consent_method": "REQUIRED",
            "issuer_mode": "ORG_URL",
            "wildcard_redirect": "DISABLED",
            "initiate_login_uri": "https://app.example.com/login",
            "idp_initiated_login": {"mode": "DISABLED"},
        },
    },
}

SAML_APP = {
    "id": "0oa2",
    "name": "acme_saml",
    "label": "Acme",
    "signOnMode": "SAML_2_0",
    "credentials": {"signing": {"kid": "kid2"}},
    "settings": {
        "app": {"password": APP_SETTING_SECRET},
        "signOn": {
            "ssoAcsUrl": "https://acme.example.com/acs",
            "audience": "urn:acme",
            "recipient": "https://acme.example.com/acs",
            "destination": "https://acme.example.com/acs",
            "assertionSigned": True,
            "responseSigned": True,
            "signatureAlgorithm": "RSA_SHA256",
            "digestAlgorithm": "SHA256",
            "honorForceAuthn": True,
            "authnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            "subjectNameIdFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "subjectNameIdTemplate": "${user.userName}",
            "idpIssuer": "http://www.okta.com/${org.externalKey}",
            "requestCompressed": False,
            "allowMultipleAcsEndpoints": False,
            "slo": {"enabled": True, "issuer": "urn:acme:slo", "logoutUrl": "https://acme.example.com/slo"},
            "spCertificate": {"x5c": ["MIIC-sp-cert"]},
        },
    },
}


def _dumped(summary) -> str:
    return json.dumps(to_jsonable(summary), default=str)


def test_oidc_detail_keeps_allowlisted_fields():
    summary = summarize_application_detail(OpenIdConnectApplication.from_dict(OIDC_APP))

    assert summary["visibility"]["autoLaunch"] is False
    oauth_settings = summary["settings"]["oauthClient"]
    assert oauth_settings["redirect_uris"] == ["https://app.example.com/cb"]
    assert oauth_settings["post_logout_redirect_uris"] == ["https://app.example.com/"]
    assert oauth_settings["initiate_login_uri"] == "https://app.example.com/login"
    assert len(oauth_settings["grant_types"]) == 2
    assert summary["settings"]["notes"] == {"admin": "owner: pe"}
    creds = summary["credentials"]
    assert creds["oauthClient"]["client_id"] == "0oaclient123"
    assert creds["oauthClient"]["autoKeyRotation"] is True
    assert creds["oauthClient"]["pkce_required"] is False
    assert creds["signing"] == {"kid": "kid1", "rotationMode": "AUTO"}


def test_oidc_detail_never_returns_secrets():
    summary = summarize_application_detail(OpenIdConnectApplication.from_dict(OIDC_APP))
    dumped = _dumped(summary)

    assert CLIENT_SECRET not in dumped
    assert 'client_secret"' not in dumped
    assert APP_SETTING_SECRET not in dumped
    assert "app" not in summary["settings"]
    assert "enduser" not in dumped


def test_saml_detail_keeps_sign_on_and_only_slo_enabled():
    summary = summarize_application_detail(SamlApplication.from_dict(SAML_APP))
    sign_on = summary["settings"]["signOn"]

    assert sign_on["ssoAcsUrl"] == "https://acme.example.com/acs"
    assert sign_on["assertionSigned"] is True
    assert sign_on["idpIssuer"] == "http://www.okta.com/${org.externalKey}"
    assert sign_on["slo"] == {"enabled": True}
    assert "subjectNameIdTemplate" not in sign_on
    assert "spCertificate" not in sign_on
    assert summary["credentials"] == {"signing": {"kid": "kid2"}}
    assert APP_SETTING_SECRET not in _dumped(summary)


def test_detail_handles_snake_case_dicts():
    raw = {
        "id": "0oa3",
        "visibility": {"auto_launch": True, "auto_submit_toolbar": False},
        "settings": {
            "app": {"secret": APP_SETTING_SECRET},
            "sign_on": {"sso_acs_url": "https://x/acs", "honor_force_authn": False, "slo": {"enabled": False}},
            "oauth_client": {"redirect_uris": ["https://x/cb"]},
        },
        "credentials": {
            "oauth_client": {"client_id": "cid", "client_secret": CLIENT_SECRET, "auto_key_rotation": False},
            "signing": {"kid": "k", "rotation_mode": "MANUAL"},
        },
    }

    summary = summarize_application_detail(raw)

    assert summary["visibility"] == {"autoLaunch": True, "autoSubmitToolbar": False}
    assert summary["settings"]["signOn"] == {
        "ssoAcsUrl": "https://x/acs",
        "honorForceAuthn": False,
        "slo": {"enabled": False},
    }
    assert summary["settings"]["oauthClient"] == {"redirect_uris": ["https://x/cb"]}
    assert summary["credentials"]["oauthClient"] == {"client_id": "cid", "autoKeyRotation": False}
    assert summary["credentials"]["signing"] == {"kid": "k", "rotationMode": "MANUAL"}
    assert CLIENT_SECRET not in _dumped(summary)
    assert APP_SETTING_SECRET not in _dumped(summary)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_get_application_returns_detail_without_secrets(mock_get_client):
    client = AsyncMock()
    client.get_application.return_value = (OpenIdConnectApplication.from_dict(OIDC_APP), MagicMock(), None)
    mock_get_client.return_value = client

    result = await get_application(ctx=MagicMock(request_context=None), app_id="0oa1")

    assert result["settings"]["oauthClient"]["redirect_uris"] == ["https://app.example.com/cb"]
    assert CLIENT_SECRET not in _dumped(result)
    assert APP_SETTING_SECRET not in _dumped(result)


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_applications_stays_compact(mock_get_client):
    client = AsyncMock()
    response = MagicMock(headers={})
    client.list_applications.return_value = ([OpenIdConnectApplication.from_dict(OIDC_APP)], response, None)
    mock_get_client.return_value = client

    result = await list_applications(ctx=MagicMock(request_context=None))
    item = result["items"][0]

    assert item["id"] == "0oa1"
    assert "settings" not in item
    assert "credentials" not in item
    assert "visibility" not in item
