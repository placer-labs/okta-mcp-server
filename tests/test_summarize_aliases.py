# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.

"""Regression tests for alias-keyed SDK model dumps.

The summarizers pick camelCase fields, so a snake_case dump silently drops
everything it is asked for.
"""

from __future__ import annotations

from okta.models.log_event import LogEvent
from okta.models.user import User

from okta_mcp_server.utils.summarize import summarize_log, summarize_user

LOG = {
    "eventType": "user.session.start",
    "published": "2026-01-01T00:00:00.000Z",
    "severity": "WARN",
    "displayMessage": "Failed login",
    "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
    "actor": {"id": "00u1", "type": "User", "displayName": "A B", "alternateId": "a@b.co"},
}


def test_log_summary_keeps_the_fields_triage_needs():
    summary = summarize_log(LogEvent.from_dict(LOG))

    assert summary["eventType"] == "user.session.start"
    assert summary["displayMessage"] == "Failed login"
    assert summary["outcome"]["result"] == "FAILURE"
    assert summary["actor"]["displayName"] == "A B"
    assert summary["actor"]["alternateId"] == "a@b.co"


def test_user_summary_keeps_camel_case_fields():
    user = User.from_dict(
        {
            "id": "00u1",
            "status": "ACTIVE",
            "lastUpdated": "2026-01-01T00:00:00.000Z",
            "profile": {"firstName": "A", "lastName": "B", "email": "a@b.co", "login": "a@b.co"},
        }
    )

    summary = summarize_user(user)

    assert summary["id"] == "00u1"
    assert summary["lastUpdated"] is not None
    assert summary["profile"]["firstName"] == "A"
    assert summary["profile"]["email"] == "a@b.co"


def test_log_summary_keeps_client_and_security_context():
    event = LogEvent.from_dict(
        {
            **LOG,
            "client": {
                "ipAddress": "203.0.113.7",
                "zone": "null",
                "device": "Computer",
                "geographicalContext": {
                    "country": "United States",
                    "state": "California",
                    "city": "San Francisco",
                    "postalCode": "94105",
                    "geolocation": {"lat": 37.7, "lon": -122.4},
                },
                "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Mac OS X", "browser": "CHROME"},
            },
            "securityContext": {"asNumber": 64496, "asOrg": "example", "isp": "example isp", "isProxy": False},
            "debugContext": {"debugData": {"requestUri": "/oauth2/v1/token?code=leaky"}},
        }
    )

    summary = summarize_log(event)

    assert summary["client"] == {
        "ipAddress": "203.0.113.7",
        "zone": "null",
        "geographicalContext": {"country": "United States", "state": "California", "city": "San Francisco"},
        "userAgent": {"rawUserAgent": "Mozilla/5.0"},
    }
    assert summary["securityContext"] == {
        "asNumber": 64496,
        "asOrg": "example",
        "isp": "example isp",
        "isProxy": False,
    }
    assert "debugContext" not in summary


def test_log_summary_omits_absent_client():
    summary = summarize_log(LogEvent.from_dict(LOG))

    assert "client" not in summary
    assert "securityContext" not in summary


def test_log_user_agent_is_capped():
    from okta_mcp_server.utils.summarize import summarize_log

    log = {"eventType": "user.session.start", "client": {"userAgent": {"rawUserAgent": "A" * 5000}}}
    assert len(summarize_log(log)["client"]["userAgent"]["rawUserAgent"]) == 256
