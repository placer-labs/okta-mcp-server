# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Device Assurance Policy tools.

The per-platform attribute matrix is derived from the Okta SDK's own discriminated
union models rather than hand-maintained here, because the SDK silently discards
attributes a platform does not accept: a policy created with the wrong shape comes
back looking fine while enforcing nothing.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import okta.models as okta_models
from fastmcp import Context
from fastmcp.exceptions import ToolError
from loguru import logger
from okta.models.device_assurance import DeviceAssurance
from pydantic import ValidationError

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import _resolve_manager, get_okta_client
from okta_mcp_server.utils.summarize import summarize_device_assurance_policies, summarize_device_assurance_policy
from okta_mcp_server.utils.validation import validate_ids, validate_os_version_params

_PLATFORM_MODELS = {
    "ANDROID": okta_models.DeviceAssuranceAndroidPlatform,
    "CHROMEOS": okta_models.DeviceAssuranceChromeOSPlatform,
    "IOS": okta_models.DeviceAssuranceIOSPlatform,
    "MACOS": okta_models.DeviceAssuranceMacOSPlatform,
    "WINDOWS": okta_models.DeviceAssuranceWindowsPlatform,
}

# Compliance checks a policy can enforce, as opposed to metadata (id, name, timestamps).
_ASSURANCE_ATTRIBUTES = frozenset(
    {
        "diskEncryptionType",
        "jailbreak",
        "osVersion",
        "osVersionConstraints",
        "screenLockType",
        "secureHardwarePresent",
    }
)

_OS_VERSION_IN_POLICY_DATA_ERROR = (
    "osVersion must NOT be included in policy_data. Pass the OS version as a separate parameter: "
    "user_stated_os_version. Set user_stated_os_version to the EXACT characters the user typed — "
    "do NOT normalize or append '.0'. Then retry this call with osVersion removed from policy_data."
)


def _platform_attributes(platform: str) -> List[str]:
    """Return the compliance attributes the SDK model accepts for *platform*."""
    model = _PLATFORM_MODELS.get((platform or "").upper())
    if model is None:
        return []
    aliases = {(field.alias or name) for name, field in model.model_fields.items()}
    return sorted(aliases & _ASSURANCE_ATTRIBUTES)


def _scope_error(operation: str, status: Any) -> str:
    scope = (
        "okta.deviceAssurance.manage" if operation in ("create", "replace", "delete") else "okta.deviceAssurance.read"
    )
    return (
        f"Authorization error (HTTP {status}) on device assurance {operation}: the OAuth client is missing the "
        f"'{scope}' scope. Grant it to the Okta OIDC app, make sure OKTA_SCOPES requests it, and re-authenticate "
        "before retrying."
    )


def _raise_okta_error(operation: str, err: Any) -> None:
    """Translate an SDK error into a ToolError, with a scope hint on 401/403."""
    status = getattr(err, "status", None) or getattr(err, "status_code", None)
    if status in (401, 403, "401", "403"):
        raise ToolError(_scope_error(operation, status))
    raise ToolError(f"Okta API error: {err}")


def _build_policy_model(raw: Dict[str, Any]) -> Any:
    """Build a DeviceAssurance model from *raw*, raising ValueError on anything the SDK would drop."""
    platform = (raw.get("platform") or "").upper()
    if not platform:
        raise ValueError("policy_data.platform is required. One of: " + ", ".join(sorted(_PLATFORM_MODELS)))
    if platform not in _PLATFORM_MODELS:
        raise ValueError(f"Unknown platform '{raw.get('platform')}'. One of: " + ", ".join(sorted(_PLATFORM_MODELS)))

    try:
        model = DeviceAssurance.from_dict(raw)
    except ValidationError as ve:
        raise ValueError(str(ve)) from ve
    if model is None:
        raise ValueError(f"policy_data could not be read as a {platform} device assurance policy.")

    rendered = model.to_dict()
    supported = _platform_attributes(platform)
    dropped = sorted(set(raw) - set(rendered))
    # A nested attribute that rendered empty was supplied under the wrong key
    # (e.g. diskEncryptionType={"type": ...} instead of {"include": [...]}).
    malformed = sorted(k for k, v in rendered.items() if isinstance(v, dict) and not v)

    if dropped:
        raise ValueError(
            f"{', '.join(dropped)} is not accepted for platform {platform} and would be silently ignored, "
            f"leaving the policy enforcing nothing for it. {platform} supports: "
            f"{', '.join(supported) or 'no compliance attributes'}."
        )
    if malformed:
        raise ValueError(
            f"{', '.join(malformed)} was supplied in a shape the API does not accept and would be silently "
            "ignored. diskEncryptionType and screenLockType both take an 'include' list, e.g. "
            'diskEncryptionType={"include": ["ALL_INTERNAL_VOLUMES"]} on macOS/Windows, '
            '{"include": ["FULL"]} on Android, screenLockType={"include": ["BIOMETRIC"]}.'
        )

    return model


def _attribute_status(policy: Dict[str, Any]) -> Dict[str, str]:
    """Mark each attribute the platform supports as configured or not_configured.

    Without this, an absent attribute reads as "checked and compliant" when it
    actually means the check was never configured.
    """
    return {
        attr: ("configured" if policy.get(attr) is not None else "not_configured")
        for attr in _platform_attributes(policy.get("platform", ""))
    }


def _enrich(policy: Dict[str, Any]) -> Dict[str, Any]:
    policy["securityAttributeStatus"] = _attribute_status(policy)
    return policy


_DIFF_SKIP_KEYS = frozenset(
    {"id", "createdBy", "createdDate", "lastUpdate", "lastUpdatedBy", "securityAttributeStatus"}
)

_IMPLICATIONS = {
    "osVersion": "Changes the minimum OS version. Devices on older versions will fail this check.",
    "osVersionConstraints": "Changes the per-version constraints devices are held to.",
    "jailbreak": "Changes whether jailbroken/rooted devices are blocked by this policy.",
    "diskEncryptionType": "Changes disk encryption requirements. Devices below the new standard will fail this check.",
    "screenLockType": "Changes screen lock requirements. Devices without the required lock will fail this check.",
    "secureHardwarePresent": "Changes whether secure hardware (e.g. TPM) is required to pass this check.",
    "name": "Policy display name updated.",
    "platform": "Target platform changed, which changes which devices this policy evaluates.",
}


def _policy_diff(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    changes = []
    for key in sorted((set(before) | set(after)) - _DIFF_SKIP_KEYS):
        if before.get(key) != after.get(key):
            changes.append(
                {
                    "attribute": key,
                    "before": before.get(key),
                    "after": after.get(key),
                    "implication": _IMPLICATIONS.get(key, f"The '{key}' setting has been modified."),
                }
            )
    return changes


def _retrieved_note() -> Dict[str, str]:
    return {
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Policies may have changed since this list was fetched. Call list_device_assurance_policies again "
            "before resolving a policy name to an ID."
        ),
    }


@mcp.tool()
@validate_os_version_params("version_threshold")
async def list_device_assurance_policies(ctx: Context | None = None, version_threshold: Optional[str] = None):
    """List all Device Assurance Policies in the Okta organization.

    Use this to audit which policies exist, compare OS version requirements, or find
    policies that do not block jailbroken/rooted devices.

    CRITICAL — OS version thresholds:
        When the request mentions a version number to filter or compare against, pass it
        verbatim as version_threshold rather than filtering the result yourself — that is
        what validates the format. If it is rejected, relay the error and ask the user for
        the exact X.Y.Z version. Never complete a version yourself: "13.3" and "13.3.0"
        are different versions.

    CRITICAL — name-to-ID resolution:
        Always call this tool again before mapping a policy name to an ID. A policy may
        have been created or deleted in the Okta UI since the last call.

    Parameters:
        version_threshold (str, optional): The exact version string the user supplied,
            used for subsequent filtering or comparison in your answer.

    Returns:
        Dict containing:
        - policies: List of policy objects, each with securityAttributeStatus marking every
            attribute the platform supports as 'configured' or 'not_configured'. An absent
            attribute means the check was never configured, NOT that devices pass it.
        - retrieved_at / note: Freshness metadata.
        - version_threshold: Echo of the validated threshold, when one was supplied.
        - error: Present on validation failures. Relay verbatim; do not treat as "no results".
    """
    logger.info("Listing device assurance policies")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        policies, response, err = await client.list_device_assurance_policies()

        if err:
            logger.error(f"Okta API error while listing device assurance policies: {err}")
            _raise_okta_error("list", err)

        result: Dict[str, Any] = dict(_retrieved_note())

        if policies is None:
            status = getattr(response, "status_code", None) or getattr(response, "status", None)
            if status in (401, 403):
                raise ToolError(_scope_error("list", status))
            # The SDK returns None (not an empty list) on the first call after start
            # when auth is still initialising; an empty list means no policies exist.
            logger.warning("SDK returned None for list_device_assurance_policies — likely transient")
            result["policies"] = []
            result["warning"] = "The API returned an unexpected empty response. Call this tool again."
            return result

        summarized = summarize_device_assurance_policies(list(policies))
        result["policies"] = [_enrich(p) for p in summarized]
        if version_threshold is not None:
            result["version_threshold"] = version_threshold

        logger.info(f"Successfully retrieved {len(result['policies'])} device assurance policy(ies)")
        return result

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while listing device assurance policies: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
async def get_device_assurance_policy(ctx: Context, device_assurance_id: str):
    """Retrieve a specific Device Assurance Policy by ID.

    Use this to inspect a policy's full configuration — platform, minimum OS version,
    disk encryption, screen lock and jailbreak/root requirements.

    This tool takes an ID, not a name. Resolve a name through a fresh
    list_device_assurance_policies() call; never from earlier results in the conversation.

    Parameters:
        device_assurance_id (str, required): The ID of the device assurance policy.

    Returns:
        Dict with the policy details plus securityAttributeStatus, which marks every
        attribute the platform supports as 'configured' or 'not_configured'.
    """
    logger.info(f"Getting device assurance policy {device_assurance_id}")
    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        policy, _, err = await client.get_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Okta API error while getting device assurance policy {device_assurance_id}: {err}")
            _raise_okta_error("get", err)

        if not policy:
            raise ToolError(
                f"Device assurance policy {device_assurance_id} returned no body. "
                "Verify the ID with list_device_assurance_policies()."
            )

        return _enrich(summarize_device_assurance_policy(policy))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while getting device assurance policy: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_os_version_params("user_stated_os_version")
async def create_device_assurance_policy(
    ctx: Context, policy_data: Dict[str, Any], user_stated_os_version: Optional[str] = None
):
    """Create a new Device Assurance Policy.

    CRITICAL — OS version:
        Do NOT put osVersion in policy_data; pass user_stated_os_version instead and the
        tool builds osVersion from it after validation. Set it to the EXACT characters the
        user typed. Never invent or complete a version — "12.1" and "12.1.0" are different.
        If it is rejected, relay the error and ask for the full X.Y.Z version.

    Attributes accepted per platform (derived from the Okta SDK models):
        - ANDROID: osVersion, jailbreak, screenLockType, diskEncryptionType, secureHardwarePresent
        - IOS: osVersion, jailbreak, screenLockType
        - MACOS: osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - WINDOWS: osVersion, osVersionConstraints, diskEncryptionType, screenLockType,
          secureHardwarePresent
        - CHROMEOS: no compliance attributes

    Anything the platform does not accept is rejected here rather than sent, because the
    API silently ignores it and returns a policy that looks configured but enforces nothing.

    Parameters:
        policy_data (dict, required): The policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): ANDROID, CHROMEOS, IOS, MACOS or WINDOWS.
            - osVersion: Do NOT include — use user_stated_os_version.
            - diskEncryptionType (dict, optional): {"include": ["ALL_INTERNAL_VOLUMES"]} on
              MACOS/WINDOWS, {"include": ["FULL"]} or {"include": ["USER"]} on ANDROID.
            - screenLockType (dict, optional): {"include": ["BIOMETRIC"]}, values from
              BIOMETRIC, PASSCODE, NONE.
            - secureHardwarePresent (bool, optional): Require secure hardware such as a TPM.
            - jailbreak (bool, optional): Block jailbroken/rooted devices.
        user_stated_os_version (str, optional): The exact OS version string the user typed.
            ANDROID accepts a bare major version (e.g. "12"); every other platform needs X.Y.Z.

    Returns:
        Dict with the created policy, or an error dict when policy_data is rejected.
    """
    logger.info("Creating new device assurance policy")
    manager = _resolve_manager(ctx)

    if not isinstance(policy_data, dict):
        return {"error": "policy_data must be an object (dict)."}

    raw = {k: v for k, v in policy_data.items() if v is not None}
    if raw.get("osVersion") and user_stated_os_version is None:
        return {"error": _OS_VERSION_IN_POLICY_DATA_ERROR}
    if user_stated_os_version:
        raw = {**raw, "osVersion": {"minimum": user_stated_os_version}}

    try:
        policy_model = _build_policy_model(raw)
    except ValueError as ve:
        logger.warning(f"Rejected device assurance policy payload: {ve}")
        return {"error": str(ve)}

    try:
        client = await get_okta_client(manager)
        policy, _, err = await client.create_device_assurance_policy(policy_model)

        if err:
            logger.error(f"Okta API error while creating device assurance policy: {err}")
            _raise_okta_error("create", err)

        if policy is None:
            raise ToolError(
                f"Creating device assurance policy {raw.get('name', 'N/A')!r} returned no body. "
                "Use list_device_assurance_policies() to confirm whether it was created."
            )

        logger.info(f"Successfully created device assurance policy {policy.id}")
        return _enrich(summarize_device_assurance_policy(policy))

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while creating device assurance policy: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
@validate_os_version_params("user_stated_os_version")
async def replace_device_assurance_policy(
    ctx: Context,
    device_assurance_id: str,
    policy_data: Dict[str, Any],
    user_stated_os_version: Optional[str] = None,
):
    """Replace (fully update) an existing Device Assurance Policy.

    This is a replace, not a merge: any attribute missing from policy_data is dropped from
    the policy. Fetch the current state first and send the complete configuration.

    CRITICAL — always show the result:
        The response carries before, after and changes. Present them as a comparison,
        including the implication of every change. Never answer with just "Done".

    CRITICAL — OS version:
        Do NOT put osVersion in policy_data; pass user_stated_os_version verbatim and the
        tool builds osVersion from it after validation. Never complete a version yourself.

    See create_device_assurance_policy for the attributes each platform accepts.

    Parameters:
        device_assurance_id (str, required): The ID of the policy to replace.
        policy_data (dict, required): The complete updated policy configuration.
        user_stated_os_version (str, optional): The exact OS version string the user typed.

    Returns:
        Dict containing:
        - before / after: Policy state either side of the change, with securityAttributeStatus.
        - changes: Each changed attribute with its before and after values and the
            security implication of the change.
    """
    logger.info(f"Replacing device assurance policy {device_assurance_id}")
    manager = _resolve_manager(ctx)

    if not isinstance(policy_data, dict):
        return {"error": "policy_data must be an object (dict)."}

    raw = {k: v for k, v in policy_data.items() if v is not None}
    if raw.get("osVersion") and user_stated_os_version is None:
        return {"error": _OS_VERSION_IN_POLICY_DATA_ERROR}
    if user_stated_os_version:
        raw = {**raw, "osVersion": {"minimum": user_stated_os_version}}

    try:
        policy_model = _build_policy_model(raw)
    except ValueError as ve:
        logger.warning(f"Rejected device assurance policy payload: {ve}")
        return {"error": str(ve)}

    try:
        client = await get_okta_client(manager)

        current, _, fetch_err = await client.get_device_assurance_policy(device_assurance_id)
        if fetch_err:
            logger.error(f"Okta API error while fetching device assurance policy {device_assurance_id}: {fetch_err}")
            _raise_okta_error("replace", fetch_err)

        before_state = _enrich(summarize_device_assurance_policy(current)) if current else {}

        policy, _, err = await client.replace_device_assurance_policy(device_assurance_id, policy_model)

        if err:
            logger.error(f"Okta API error while replacing device assurance policy {device_assurance_id}: {err}")
            _raise_okta_error("replace", err)

        if not policy:
            raise ToolError(
                f"Replacing device assurance policy {device_assurance_id} returned no body. "
                "Re-fetch with get_device_assurance_policy() to confirm the current state."
            )

        after_state = _enrich(summarize_device_assurance_policy(policy))

        logger.info(f"Successfully replaced device assurance policy {device_assurance_id}")
        return {
            "before": before_state,
            "after": after_state,
            "changes": _policy_diff(before_state, after_state),
        }

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while replacing device assurance policy: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
def delete_device_assurance_policy(ctx: Context, device_assurance_id: str):
    """Delete a Device Assurance Policy, after confirmation.

    IMPORTANT: after calling this, STOP and wait for the user to type 'DELETE'. Do NOT
    call confirm_delete_device_assurance_policy yourself.

    A policy still referenced by an authentication policy cannot be deleted.

    Parameters:
        device_assurance_id (str, required): The ID of the policy to delete.

    Returns:
        List containing the confirmation request.
    """
    logger.warning(f"Deletion requested for device assurance policy {device_assurance_id}, awaiting confirmation")
    return [
        {
            "confirmation_required": True,
            "message": (
                f"To confirm deletion of device assurance policy {device_assurance_id}, please type 'DELETE'. "
                "Devices will no longer be evaluated against it."
            ),
            "device_assurance_id": device_assurance_id,
        }
    ]


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
async def confirm_delete_device_assurance_policy(ctx: Context, device_assurance_id: str, confirmation: str):
    """Execute a device assurance policy deletion after the user has confirmed it.

    Only call this once the user has explicitly typed 'DELETE'. Never call it automatically
    after delete_device_assurance_policy.

    Parameters:
        device_assurance_id (str, required): The ID of the policy to delete.
        confirmation (str, required): Must be 'DELETE' to proceed.

    Returns:
        List containing the result of the deletion.
    """
    logger.info(f"Processing deletion confirmation for device assurance policy {device_assurance_id}")

    if confirmation != "DELETE":
        logger.warning(f"Deletion cancelled for {device_assurance_id} - incorrect confirmation")
        return [{"error": "Deletion cancelled. Confirmation 'DELETE' was not provided correctly."}]

    manager = _resolve_manager(ctx)

    try:
        client = await get_okta_client(manager)
        _, _, err = await client.delete_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Okta API error while deleting device assurance policy {device_assurance_id}: {err}")
            _raise_okta_error("delete", err)

        logger.info(f"Device assurance policy {device_assurance_id} deleted successfully")
        return [{"message": f"Device assurance policy {device_assurance_id} deleted successfully"}]

    except ToolError:
        raise
    except Exception as e:
        logger.error(f"Exception while deleting device assurance policy: {type(e).__name__}: {e}")
        raise ToolError(f"Exception: {e}") from e
