# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
from typing import Any, Optional

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    has_next_page,
    paginate_all_results,
)
from okta_mcp_server.utils.summarize import summarize_logs

# Workarounds for SDK v3 schema bugs that crash get_logs on real Okta data.
# Each monkey-patch relaxes an overly-strict Pydantic constraint that doesn't
# match what the API actually returns; remove these as the upstream SDK ships
# matching schema fixes.
try:
    import typing as _typing

    from okta.models.log_outcome import LogOutcome as _LogOutcome
    from okta.models.log_security_context import LogSecurityContext as _LogSecurityContext

    # 1. LogSecurityContext.user_behaviors: declared List[StrictStr] but Behavior
    #    Detection events return List[dict].
    _user_behaviors_type = _typing.Optional[_typing.List[_typing.Any]]
    _LogSecurityContext.__annotations__["user_behaviors"] = _user_behaviors_type
    if "user_behaviors" in _LogSecurityContext.model_fields:
        _LogSecurityContext.model_fields["user_behaviors"].annotation = _user_behaviors_type
    _LogSecurityContext.model_rebuild(force=True)

    # 2. LogOutcome.reason: declared with MaxLen(255) but real values like
    #    "Password requirements were not met..." routinely exceed that.
    _reason_type = _typing.Optional[str]
    _LogOutcome.__annotations__["reason"] = _reason_type
    if "reason" in _LogOutcome.model_fields:
        _LogOutcome.model_fields["reason"].annotation = _reason_type
        _LogOutcome.model_fields["reason"].metadata = []
    _LogOutcome.model_rebuild(force=True)

    logger.debug("Applied SDK v3 schema workarounds: LogSecurityContext.user_behaviors, LogOutcome.reason")
except Exception as _patch_err:  # pragma: no cover - defensive
    logger.warning(f"Could not apply SDK v3 schema workarounds: {_patch_err}")

_VALID_OUTCOME_RESULTS = {"SUCCESS", "FAILURE", "DENY", "ALLOW", "CHALLENGE", "UNKNOWN"}
_MFA_EVENT_TYPE_PATTERN = re.compile(
    r'eventType\s+eq\s+["\'].*(?:mfa|factor|verify|challenge|step.?up|authentication).*["\']',
    re.IGNORECASE,
)


def check_logs_scope_error(err_or_exc: Any) -> Optional[str]:
    """Return a user-friendly scope-error message for 403 / insufficient_scope, else None."""
    err_str = str(err_or_exc)
    err_status = (
        getattr(err_or_exc, "status", None)
        or getattr(err_or_exc, "status_code", None)
        or getattr(err_or_exc, "errorCode", None)
    )
    is_403 = (
        err_status in (403, "403")
        or "403" in err_str
        or "insufficient_scope" in err_str.lower()
        or "access_denied" in err_str.lower()
        or "okta.logs.read" in err_str.lower()
        or "E0000005" in err_str
        or "E0000006" in err_str
    )
    if is_403:
        return (
            "Authorization error (HTTP 403): the OAuth client does not have the "
            "'okta.logs.read' scope. Ensure this scope is granted to the OAuth application "
            "and that the current session was authenticated with it. "
            f"Okta error details: {err_or_exc}"
        )
    return None


def _add_failure_deny_reminder(result: dict, filter_str: Optional[str]) -> None:
    """Mutate result in-place: add a reminder when only FAILURE or only DENY was queried."""
    fs = filter_str or ""
    has_failure = bool(re.search(r'outcome\.result\s+eq\s+["\']FAILURE["\']', fs, re.IGNORECASE))
    has_deny = bool(re.search(r'outcome\.result\s+eq\s+["\']DENY["\']', fs, re.IGNORECASE))
    if has_failure and not has_deny:
        result["reminder"] = (
            "FAILURE results fetched. You MUST NOW make a second separate call: "
            "get_logs(filter='outcome.result eq \"DENY\"', fetch_all=True, since=..., until=...) "
            "— policy-blocked sign-ins are a separate outcome and will NOT appear in FAILURE results."
        )
    elif has_deny and not has_failure:
        result["reminder"] = (
            "DENY results fetched. You MUST NOW make a second separate call: "
            "get_logs(filter='outcome.result eq \"FAILURE\"', fetch_all=True, since=..., until=...) "
            "— authentication failures are a separate outcome and will NOT appear in DENY results."
        )


@mcp.tool()
async def get_logs(
    ctx: Context | None = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    filter: Optional[str] = None,
    q: Optional[str] = None,
):
    """Retrieve system logs from the Okta organization with pagination support.

    CRITICAL — login failure investigation:
        FAILURE and DENY are TWO SEPARATE outcome values. A single call is NEVER sufficient
        when investigating login failures. Always make BOTH calls:
          1. get_logs(filter='outcome.result eq "FAILURE"', fetch_all=True, ...)
          2. get_logs(filter='outcome.result eq "DENY"', fetch_all=True, ...)
        FAILURE = wrong password, locked account, MFA not completed.
        DENY    = blocked by sign-on policy (IP / device / policy violation).
        Skipping either silently misses an entire category of failures.

    CRITICAL — MFA challenges:
        Use filter='outcome.result eq "CHALLENGE"'. Do NOT filter by eventType for
        MFA / step-up / factor verify queries — that returns the wrong slice.

    Parameters:
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
            Use fetch_all=True for any "all", "complete", "total", "how many" question.
            Always pair with a since/until time window. Capped at 50 pages.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of log entries to return per page (min 20, max 100).
        since (str, optional): Filter logs since this timestamp (ISO 8601 format).
        until (str, optional): Filter logs until this timestamp (ISO 8601 format).
        filter (str, optional): Filter expression for log events. The only valid values for
            outcome.result are: SUCCESS, FAILURE, DENY, ALLOW, CHALLENGE, UNKNOWN. Any other
            value will return an error from this tool — do not filter the value yourself.
        q (str, optional): Query string to search log events.

    Examples:
        - First call: get_logs()
        - Next page: get_logs(after="cursor_value")
        - All pages: get_logs(fetch_all=True)
        - Time range: get_logs(since="2024-01-01T00:00:00.000Z", until="2024-01-02T00:00:00.000Z")
        - Policy-blocked logins: get_logs(filter='outcome.result eq "DENY"', fetch_all=True)
        - Auth failures: get_logs(filter='outcome.result eq "FAILURE"', fetch_all=True)
        - MFA challenges: get_logs(filter='outcome.result eq "CHALLENGE"', fetch_all=True)

    Returns:
        Dict containing:
        - items: List of log entry objects
        - total_fetched: Number of log entries returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
        - reminder: Present when only FAILURE or only DENY was queried — reminds the caller
            to make the paired call.
        - error: Present on validation failures (invalid outcome value, MFA-by-eventType filter,
            scope error). Always relay the message verbatim; do not treat as "no results".
    """
    logger.info("Retrieving system logs from Okta organization")
    logger.debug(f"fetch_all: {fetch_all}, after: '{after}', limit: {limit}, since: '{since}', until: '{until}'")

    # Validate limit parameter range
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    # Detect MFA-related eventType filters that should use outcome.result eq "CHALLENGE".
    if filter and _MFA_EVENT_TYPE_PATTERN.search(filter):
        has_challenge_filter = bool(re.search(r'outcome\.result\s+eq\s+["\']CHALLENGE["\']', filter, re.IGNORECASE))
        if not has_challenge_filter:
            return {
                "error": (
                    "Incorrect filter for MFA challenge queries. Do NOT use eventType filters for "
                    "MFA challenges. You MUST use: filter='outcome.result eq \"CHALLENGE\"' "
                    "(optionally combined with actor.id). Retry with the correct filter."
                )
            }

    # Validate outcome.result value if present in the filter.
    if filter:
        outcome_match = re.search(r'outcome\.result\s+eq\s+["\']([^"\']+)["\']', filter, re.IGNORECASE)
        if outcome_match:
            outcome_value = outcome_match.group(1).upper()
            if outcome_value not in _VALID_OUTCOME_RESULTS:
                logger.warning(f"Invalid outcome.result value in filter: '{outcome_match.group(1)}'")
                return {
                    "error": (
                        f"Invalid outcome.result value: '{outcome_match.group(1)}'. "
                        f"Valid values: {', '.join(sorted(_VALID_OUTCOME_RESULTS))}. "
                        "Note: DENY is for policy-blocked logins, FAILURE is for authentication "
                        "failures (wrong password, locked account). For MFA challenges use CHALLENGE."
                    )
                }

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        logger.debug("Calling Okta API to retrieve system logs")

        query_params = build_query_params(after=after, limit=limit, since=since, until=until, filter=filter, q=q)

        logs, response, err = await client.list_log_events(**query_params)

        if err:
            logger.error(f"Okta API error while retrieving system logs: {err}")
            scope_msg = check_logs_scope_error(err)
            if scope_msg:
                raise ToolError(scope_msg)
            raise ToolError(f"Okta API error: {err}")

        if not logs:
            logger.info("No system logs found")
            result = create_paginated_response([], response, fetch_all)
            _add_failure_deny_reminder(result, filter)
            return result

        log_count = len(logs)
        logger.debug(f"Retrieved {log_count} system log entries in first page")

        if log_count > 0:
            logger.debug(f"First log entry timestamp: {logs[0].published if hasattr(logs[0], 'published') else 'N/A'}")
            logger.debug(f"Log types found: {set(log.event_type for log in logs[:10] if hasattr(log, 'event_type'))}")

        if fetch_all and has_next_page(response):
            logger.info(f"fetch_all=True, auto-paginating from initial {log_count} log entries")
            all_logs, pagination_info = await paginate_all_results(
                client.list_log_events, query_params, logs, response
            )

            logger.info(
                f"Successfully retrieved {len(all_logs)} log entries across {pagination_info['pages_fetched']} pages"
            )
            result = create_paginated_response(
                summarize_logs(all_logs), response, fetch_all_used=True, pagination_info=pagination_info
            )
            _add_failure_deny_reminder(result, filter)
            return result

        logger.info(f"Successfully retrieved {log_count} system log entries")
        result = create_paginated_response(summarize_logs(logs), response, fetch_all_used=fetch_all)
        _add_failure_deny_reminder(result, filter)
        return result

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while retrieving system logs: {type(e).__name__}: {e}")
        scope_msg = check_logs_scope_error(e)
        if scope_msg:
            raise ToolError(scope_msg)
        raise ToolError(f"Exception: {e}") from e
