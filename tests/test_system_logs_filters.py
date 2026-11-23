"""get_logs rejects eventType filters for MFA challenges, but not for MFA factor lifecycle events."""

import pytest

from okta_mcp_server.tools.system_logs.system_logs import _MFA_CHALLENGE_EVENT_TYPE_PATTERN


@pytest.mark.parametrize(
    "filter_expr",
    [
        'eventType eq "user.authentication.auth_via_mfa.challenge"',
        "eventType eq 'policy.evaluate_sign_on.step_up'",
        'eventType eq "system.stepup.required"',
    ],
)
def test_challenge_event_type_filters_are_rejected(filter_expr):
    assert _MFA_CHALLENGE_EVENT_TYPE_PATTERN.search(filter_expr)


@pytest.mark.parametrize(
    "filter_expr",
    [
        'eventType eq "user.mfa.factor.deactivate"',
        'eventType eq "user.mfa.factor.reset_all"',
        'eventType eq "user.mfa.factor.activate"',
        'eventType eq "user.authentication.verify"',
        'outcome.result eq "CHALLENGE"',
    ],
)
def test_factor_lifecycle_and_outcome_filters_are_allowed(filter_expr):
    assert not _MFA_CHALLENGE_EVENT_TYPE_PATTERN.search(filter_expr)
