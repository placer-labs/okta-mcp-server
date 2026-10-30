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

import re
from typing import Any, Dict, List, Optional


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


def _snake(key: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def _sub(source: Any, key: str) -> Dict[str, Any]:
    """Return the nested object at *key* (camelCase or snake_case) as a dict, or {}."""
    if not isinstance(source, dict):
        return {}
    value = source.get(key)
    if value is None:
        value = source.get(_snake(key))
    if value is None:
        return {}
    return _obj_to_dict(value)


def _pick_either(source: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    """Like ``_pick`` but also matches the snake_case form; output is keyed by *keys*."""
    out: Dict[str, Any] = {}
    for k in keys:
        v = source.get(k)
        if v is None:
            v = source.get(_snake(k))
        if v is not None:
            out[k] = v
    return out


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


# Allowlists only: settings.app and credential secrets must never be surfaced.
_APP_VISIBILITY_FIELDS = ["autoLaunch", "autoSubmitToolbar", "hide"]
_APP_OAUTH_SETTINGS_FIELDS = [
    "redirect_uris",
    "post_logout_redirect_uris",
    "grant_types",
    "response_types",
    "application_type",
    "consent_method",
    "issuer_mode",
    "wildcard_redirect",
    "pkce_required",
    "initiate_login_uri",
    "idp_initiated_login",
]
_APP_OAUTH_CREDENTIAL_FIELDS = ["client_id", "token_endpoint_auth_method", "pkce_required", "autoKeyRotation"]
_APP_SIGNING_FIELDS = ["kid", "rotationMode"]
_APP_SAML_SIGN_ON_FIELDS = [
    "ssoAcsUrl",
    "audience",
    "recipient",
    "destination",
    "assertionSigned",
    "responseSigned",
    "signatureAlgorithm",
    "digestAlgorithm",
    "honorForceAuthn",
    "authnContextClassRef",
    "subjectNameIdFormat",
    "idpIssuer",
    "requestCompressed",
    "allowMultipleAcsEndpoints",
]


def _compact(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, {})}


def summarize_application_detail(app: Any) -> Dict[str, Any]:
    """Return the compact summary plus allowlisted security-relevant settings and credentials."""
    d = _obj_to_dict(app)
    result = _pick(d, _APP_FIELDS)

    visibility = _pick_either(_sub(d, "visibility"), _APP_VISIBILITY_FIELDS)
    if visibility:
        result["visibility"] = visibility

    settings = _sub(d, "settings")
    sign_on = _pick_either(_sub(settings, "signOn"), _APP_SAML_SIGN_ON_FIELDS)
    slo_enabled = _sub(_sub(settings, "signOn"), "slo").get("enabled")
    if slo_enabled is not None:
        sign_on["slo"] = {"enabled": slo_enabled}
    admin_note = _sub(settings, "notes").get("admin")
    settings_out = _compact(
        {
            "oauthClient": _pick_either(_sub(settings, "oauthClient"), _APP_OAUTH_SETTINGS_FIELDS),
            "signOn": sign_on,
            "notes": {"admin": admin_note} if admin_note is not None else None,
        }
    )
    if settings_out:
        result["settings"] = settings_out

    credentials = _sub(d, "credentials")
    credentials_out = _compact(
        {
            "oauthClient": _pick_either(_sub(credentials, "oauthClient"), _APP_OAUTH_CREDENTIAL_FIELDS),
            "signing": _pick_either(_sub(credentials, "signing"), _APP_SIGNING_FIELDS),
        }
    )
    if credentials_out:
        result["credentials"] = credentials_out
    return result


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
_LOG_GEO_FIELDS = ["country", "state", "city"]
_LOG_SECURITY_CONTEXT_FIELDS = ["asNumber", "asOrg", "isp", "isProxy"]


def _summarize_log_client(d: Dict[str, Any]) -> Dict[str, Any]:
    client = _sub(d, "client")
    out = _pick_either(client, ["ipAddress", "zone"])
    geo = _pick_either(_sub(client, "geographicalContext"), _LOG_GEO_FIELDS)
    if geo:
        out["geographicalContext"] = geo
    raw_ua = _pick_either(_sub(client, "userAgent"), ["rawUserAgent"])
    if raw_ua:
        out["userAgent"] = raw_ua
    return out


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
    client = _summarize_log_client(d)
    if client:
        result["client"] = client
    security_context = _pick_either(_sub(d, "securityContext"), _LOG_SECURITY_CONTEXT_FIELDS)
    if security_context:
        result["securityContext"] = security_context
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


# ── Device Assurance ──────────────────────────────────────────

_DEVICE_ASSURANCE_DROP_KEYS = {"_links", "links"}


def summarize_device_assurance_policy(policy: Any) -> Dict[str, Any]:
    """Return a device assurance policy without its HAL link metadata.

    Every other field is kept: the set of compliance attributes differs per platform
    and grows with the SDK, so an allow-list here would silently hide new checks.
    """
    if not isinstance(policy, dict):
        # to_dict() omits unset fields, so an absent attribute reads as
        # "not configured"; a full model dump would spell out every null.
        policy = policy.to_dict() if hasattr(policy, "to_dict") else _obj_to_dict(policy)
    return {k: v for k, v in policy.items() if k not in _DEVICE_ASSURANCE_DROP_KEYS}


def summarize_device_assurance_policies(policies: List[Any]) -> List[Dict[str, Any]]:
    """Summarize a list of device assurance policies."""
    return [summarize_device_assurance_policy(p) for p in policies]


# ── API tokens ────────────────────────────────────────────────

_API_TOKEN_FIELDS = [
    "id",
    "name",
    "userId",
    "clientName",
    "created",
    "lastUpdated",
    "expiresAt",
    "network",
    "tokenWindow",
]


def summarize_api_token(token: Any) -> Dict[str, Any]:
    """Return API token metadata. The API never returns token values; this allowlist keeps it that way."""
    return _pick_either(_obj_to_dict(token), _API_TOKEN_FIELDS)


def summarize_api_tokens(tokens: List[Any]) -> List[Dict[str, Any]]:
    return [summarize_api_token(t) for t in tokens]


# ── Authenticators ────────────────────────────────────────────

_AUTHENTICATOR_FIELDS = ["id", "key", "name", "status", "type", "created", "lastUpdated"]
_SECRET_KEY_RE = re.compile(r"secret|password|private|hmac|credential|integration_?key|api_?key", re.IGNORECASE)


def _scrub(value: Any) -> Any:
    """Recursively drop keys that look like secrets."""
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if not _SECRET_KEY_RE.search(str(k))}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if hasattr(value, "model_dump"):
        return _scrub(_obj_to_dict(value))
    return value


def summarize_authenticator(authenticator: Any) -> Dict[str, Any]:
    """Return an authenticator's identity, status and settings; provider configuration (Duo keys etc.) is omitted."""
    d = _obj_to_dict(authenticator)
    result = _pick_either(d, _AUTHENTICATOR_FIELDS)
    settings = _sub(d, "settings")
    if settings:
        result["settings"] = _scrub(settings)
    provider_type = _sub(d, "provider").get("type")
    if provider_type is not None:
        result["provider"] = {"type": provider_type}
    return result


def summarize_authenticators(authenticators: List[Any]) -> List[Dict[str, Any]]:
    return [summarize_authenticator(a) for a in authenticators]


# ── Admin roles ───────────────────────────────────────────────

_ROLE_FIELDS = ["id", "type", "label", "assignmentType", "status", "role", "resource-set", "created", "lastUpdated"]


def summarize_role(role: Any) -> Dict[str, Any]:
    """Return a role assignment, unwrapping the SDK's oneOf (StandardRole | CustomRole) container."""
    inner: Optional[Any] = getattr(role, "actual_instance", None)
    d = _obj_to_dict(inner if inner is not None else role)
    out = _pick_either(d, _ROLE_FIELDS)
    if "resource-set" not in out and d.get("resource_set") is not None:
        out["resource-set"] = d["resource_set"]
    return out


def summarize_roles(roles: List[Any]) -> List[Dict[str, Any]]:
    return [summarize_role(r) for r in roles]
