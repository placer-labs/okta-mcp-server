# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Utilities to produce compact summaries of Okta SDK objects.

Okta SDK model objects carry many nested fields (_links, embedded resources,
internal metadata) that balloon MCP tool responses to tens of thousands of
characters.  The helpers here convert SDK objects to slim dictionaries that
retain the fields an LLM actually needs for reasoning while dramatically
reducing token usage.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _obj_to_dict(obj: Any) -> Dict[str, Any]:
    """Convert an Okta SDK object to a plain dictionary.

    Tries ``as_dict()`` first (available on most Okta SDK models),
    falls back to ``vars()``, and finally treats the object as already
    a dict.
    """
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        # by_alias keys the dump the way the API does (camelCase), matching the
        # field lists below; the snake_case default made them all miss.
        # warnings=False suppresses Pydantic serializer warnings for models that
        # were reconstructed leniently (see okta_compat) and therefore hold raw
        # enum strings / nested dicts instead of typed sub-models.
        return obj.model_dump(by_alias=True, warnings=False)
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return {"value": str(obj)}


def _pick(source: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """Return a new dict containing only *keys* that exist in *source*."""
    return {k: source[k] for k in keys if k in source}


# ── Applications ──────────────────────────────────────────────────────────

_APP_FIELDS = [
    "id",
    "name",
    "label",
    "status",
    "signOnMode",
    "created",
    "lastUpdated",
    "features",
    "accessibility",
]


def summarize_application(app: Any) -> Dict[str, Any]:
    """Return a compact summary of an Application object."""
    d = _obj_to_dict(app)
    return _pick(d, _APP_FIELDS)


def summarize_applications(apps: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of Application objects."""
    return [summarize_application(a) for a in apps]


# ── Groups ────────────────────────────────────────────────────────────────

_GROUP_FIELDS = [
    "id",
    "type",
    "profile",
    "created",
    "lastUpdated",
    "lastMembershipUpdated",
    "objectClass",
]


def _pick_alias(d: Dict[str, Any], *keys: str) -> Any:
    """Return the first present value across alias / snake_case key variants."""
    for k in keys:
        v = d.get(k)
        if v is not None:
            return v
    return None


def summarize_group(group: Any) -> Dict[str, Any]:
    """Return a compact summary of a Group object.

    When the group was fetched with ``expand=stats``, the embedded counts
    are surfaced as ``users_count``, ``apps_count``, and
    ``has_admin_privilege`` so callers can audit groups without separately
    listing members or apps. The SDK's underlying field names use both
    snake_case (Python attr) and camelCase (alias) depending on whether the
    upstream dump used ``by_alias=True``, so both variants are handled.

    Note: the Okta SDK exposes the admin-privilege field as
    ``has_admin_privlege`` (with a missing 'i' — a typo inherited from the
    Okta API spec). It is surfaced here under the corrected key
    ``has_admin_privilege``.
    """
    d = _obj_to_dict(group)
    out = _pick(d, _GROUP_FIELDS)
    embedded = d.get("embedded") or d.get("_embedded")
    if isinstance(embedded, dict):
        stats = embedded.get("stats")
        if isinstance(stats, dict):
            users_count = _pick_alias(stats, "usersCount", "users_count")
            if users_count is not None:
                out["users_count"] = users_count
            apps_count = _pick_alias(stats, "appsCount", "apps_count")
            if apps_count is not None:
                out["apps_count"] = apps_count
            push_count = _pick_alias(stats, "groupPushMappingsCount", "group_push_mappings_count")
            if push_count is not None:
                out["group_push_mappings_count"] = push_count
            has_admin = _pick_alias(stats, "hasAdminPrivlege", "has_admin_privlege")
            if has_admin is not None:
                out["has_admin_privilege"] = has_admin
    return out


def summarize_groups(groups: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of Group objects."""
    return [summarize_group(g) for g in groups]


# ── Users ─────────────────────────────────────────────────────────────────

_USER_FIELDS = [
    "id",
    "status",
    "created",
    "lastUpdated",
    "profile",
    "type",
]

_USER_PROFILE_FIELDS = [
    "login",
    "email",
    "firstName",
    "lastName",
    "displayName",
    "department",
    "title",
    "organization",
]


def _summarize_profile(profile: Any) -> Dict[str, Any]:
    """Return a compact summary of a user profile."""
    d = _obj_to_dict(profile)
    return _pick(d, _USER_PROFILE_FIELDS)


def summarize_user(user: Any) -> Dict[str, Any]:
    """Return a compact summary of a User object."""
    d = _obj_to_dict(user)
    result = _pick(d, _USER_FIELDS)
    if "profile" in result and result["profile"] is not None:
        result["profile"] = _summarize_profile(result["profile"])
    return result


def summarize_users(users: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of User objects."""
    return [summarize_user(u) for u in users]


# ── System Logs ───────────────────────────────────────────────────────────

_LOG_FIELDS = [
    "published",
    "eventType",
    "severity",
    "displayMessage",
    "outcome",
]

_LOG_ACTOR_FIELDS = ["id", "type", "displayName", "alternateId"]
_LOG_TARGET_FIELDS = ["id", "type", "displayName", "alternateId"]


def summarize_log(log: Any) -> Dict[str, Any]:
    """Return a compact summary of a LogEvent object."""
    d = _obj_to_dict(log)
    result = _pick(d, _LOG_FIELDS)
    # Slim down actor
    if "actor" in d and d["actor"] is not None:
        actor = _obj_to_dict(d["actor"])
        result["actor"] = _pick(actor, _LOG_ACTOR_FIELDS)
    # Slim down targets
    if "target" in d and d["target"] is not None:
        targets = d["target"]
        if isinstance(targets, list):
            result["target"] = [_pick(_obj_to_dict(t), _LOG_TARGET_FIELDS) for t in targets]
        else:
            result["target"] = _obj_to_dict(targets)
    return result


def summarize_logs(logs: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of LogEvent objects."""
    return [summarize_log(log) for log in logs]


# ── Policies ──────────────────────────────────────────────────────────────

_POLICY_FIELDS = [
    "id",
    "name",
    "type",
    "status",
    "description",
    "priority",
    "created",
    "lastUpdated",
    "conditions",
    "settings",
    "system",
]

_POLICY_RULE_FIELDS = [
    "id",
    "name",
    "type",
    "status",
    "priority",
    "created",
    "lastUpdated",
    "conditions",
    "actions",
    "system",
]


def summarize_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact summary of a Policy dict (already from as_dict())."""
    if not isinstance(policy, dict):
        policy = _obj_to_dict(policy)
    return _pick(policy, _POLICY_FIELDS)


def summarize_policies(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Summarize a list of Policy dicts."""
    return [summarize_policy(p) for p in policies]


def summarize_policy_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact summary of a PolicyRule dict."""
    if not isinstance(rule, dict):
        rule = _obj_to_dict(rule)
    return _pick(rule, _POLICY_RULE_FIELDS)


def summarize_policy_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Summarize a list of PolicyRule dicts."""
    return [summarize_policy_rule(r) for r in rules]


# ── Group Rules ──────────────────────────────────────────────
_GROUP_RULE_FIELDS = [
    "id",
    "name",
    "type",
    "status",
    "created",
    "lastUpdated",
    "conditions",
    "actions",
]


def summarize_group_rule(rule: Any) -> Dict[str, Any]:
    """Return a compact summary of a GroupRule dict."""
    if not isinstance(rule, dict):
        rule = _obj_to_dict(rule)
    return _pick(rule, _GROUP_RULE_FIELDS)


def summarize_group_rules(rules: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of GroupRule dicts."""
    return [summarize_group_rule(r) for r in rules]

