# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Login failure investigation.

FAILURE and DENY are separate outcome values in the system log, so a single
get_logs call always misses one of them. This queries both and returns one
categorised response, rather than relying on the caller to make the paired call.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger

from okta_mcp_server.server import mcp
from okta_mcp_server.tools.system_logs.system_logs import check_logs_scope_error
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.pagination import build_query_params, has_next_page, paginate_all_results
from okta_mcp_server.utils.summarize import summarize_logs

# eventTypes that represent a sign-in attempt, as opposed to the token, DNS and
# other incidental events that share the same outcome.
_LOGIN_EVENT_TYPES = frozenset(
    {
        "app.generic.unauth_app_access_attempt",
        "policy.evaluate_sign_on",
        "user.authentication.auth_via_IDP",
        "user.authentication.auth_via_mfa",
        "user.authentication.auth_via_radius",
        "user.authentication.auth_via_social",
        "user.authentication.sso",
        "user.session.start",
    }
)


def _event_type(event: Any) -> str:
    if isinstance(event, dict):
        return event.get("eventType") or event.get("event_type") or ""
    return getattr(event, "event_type", "") or ""


def _categorise(events: List[Any]) -> Dict[str, List[Any]]:
    """Split events into sign-in attempts and everything else."""
    login_events = [e for e in events if _event_type(e) in _LOGIN_EVENT_TYPES]
    other_events = [e for e in events if _event_type(e) not in _LOGIN_EVENT_TYPES]
    return {"login_events": login_events, "other_events": other_events}


async def _fetch_outcome(
    client: Any,
    outcome: str,
    *,
    since: str,
    until: str,
    user_id: Optional[str] = None,
    q: Optional[str] = None,
) -> Tuple[List[Any], Dict[str, Any]]:
    """Fetch every page of log events for one outcome value."""
    filter_expr = f'outcome.result eq "{outcome}"'
    if user_id:
        filter_expr += f' and actor.id eq "{user_id}"'

    query_params = build_query_params(limit=100, since=since, until=until, filter=filter_expr, q=q)

    logs, response, err = await client.list_log_events(**query_params)

    if err:
        logger.error(f"Okta API error for outcome={outcome}: {err}")
        scope_msg = check_logs_scope_error(err)
        if scope_msg:
            raise ToolError(scope_msg)
        raise ToolError(f"Okta API error: {err}")

    if not logs:
        return [], {"pages_fetched": 1, "total_items": 0, "stopped_early": False, "stop_reason": None}

    if has_next_page(response):
        return await paginate_all_results(client.list_log_events, query_params, logs, response)

    return logs, {"pages_fetched": 1, "total_items": len(logs), "stopped_early": False, "stop_reason": None}


@mcp.tool()
async def get_login_failures(
    ctx: Context | None = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    user_id: Optional[str] = None,
    q: Optional[str] = None,
):
    """Investigate why a user failed to log in, covering authentication failures AND policy-blocked sign-ins.

    Use this instead of get_logs whenever the question is about failed logins, sign-in
    problems, why someone cannot log in, authentication errors, denied or blocked access.

    Both outcome values are queried in one call:
        FAILURE — wrong password, invalid MFA, locked account, expired credentials.
        DENY    — blocked by a sign-on policy (IP restriction, device trust, geo-fencing).
    A single get_logs call returns only one of the two, which is why it is the wrong tool
    for this question.

    Parameters:
        since (str, optional): Start of the window (ISO 8601). Defaults to 24 hours ago.
        until (str, optional): End of the window (ISO 8601). Defaults to now.
        user_id (str, optional): Okta user ID to scope the search to. Find it with list_users.
        q (str, optional): Free-text search across log fields, e.g. a user's email.

    Returns:
        Dict containing:
        - failures / denials: Each with login_events (sign-in attempts), other_events
            (incidental events sharing the outcome), total, and pagination metadata.
        - summary: Counts in one line.
        - time_window: The since/until range actually used.
        - warnings: Present when either query hit the page limit and results are partial.
        - scoped_to_user: Present when user_id was supplied.
    """
    logger.info("Investigating login failures (FAILURE + DENY)")

    now = datetime.now(timezone.utc)
    since = since or (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    until = until or now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    logger.debug(f"Time window: {since} → {until}, user_id={user_id}, q={q}")

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)

        (failure_events, failure_pagination), (deny_events, deny_pagination) = await asyncio.gather(
            _fetch_outcome(client, "FAILURE", since=since, until=until, user_id=user_id, q=q),
            _fetch_outcome(client, "DENY", since=since, until=until, user_id=user_id, q=q),
        )
    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while investigating login failures: {type(e).__name__}: {e}")
        scope_msg = check_logs_scope_error(e)
        if scope_msg:
            raise ToolError(scope_msg) from e
        raise ToolError(f"Exception: {e}") from e

    failures = _categorise(summarize_logs(failure_events))
    denials = _categorise(summarize_logs(deny_events))

    counts = [
        (len(failures["login_events"]), "authentication failure(s) (wrong password, MFA error, locked account)"),
        (len(denials["login_events"]), "policy denial(s) (blocked by a sign-on policy rule)"),
        (len(failures["other_events"]), "other FAILURE event(s) (token errors, DNS checks)"),
        (len(denials["other_events"]), "other DENY event(s)"),
    ]
    described = [f"{count} {label}" for count, label in counts if count]
    summary = (
        "Found: " + "; ".join(described) + "."
        if described
        else "No login failures or policy denials found in this time window."
    )

    result: Dict[str, Any] = {
        "failures": {**failures, "total": len(failure_events), "pagination": failure_pagination},
        "denials": {**denials, "total": len(deny_events), "pagination": deny_pagination},
        "summary": summary,
        "time_window": {"since": since, "until": until},
    }

    warnings = [
        f"{outcome} query hit the page limit — results may be incomplete. Narrow the time window."
        for outcome, pagination in (("FAILURE", failure_pagination), ("DENY", deny_pagination))
        if pagination.get("stopped_early")
    ]
    if warnings:
        result["warnings"] = warnings

    if user_id:
        result["scoped_to_user"] = user_id

    logger.info(
        f"Login failure investigation complete: {len(failure_events)} FAILURE + {len(deny_events)} DENY events "
        f"({len(failures['login_events'])} + {len(denials['login_events'])} sign-in related)"
    )

    return result
