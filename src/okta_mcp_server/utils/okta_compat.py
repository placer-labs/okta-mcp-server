# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Compatibility shims that make the Okta SDK tolerant of real-world API responses.

The Okta SDK ships auto-generated Pydantic models (``SamlApplication``,
``BrowserPluginApplication``, ...) that mark fields as *required* and constrain
some fields to fixed enums. Live orgs legitimately return apps that omit those
fields or use other values, for example:

* SAML apps missing ``settings.signOn.assertionSigned`` / ``responseSigned`` /
  ``honorForceAuthn`` / ``requestCompressed`` / ``allowMultipleAcsEndpoints``.
* Browser-plugin apps whose ``name`` is not one of the SDK's hard-coded template
  names (e.g. ``hellosign_hellofax``).

``okta.api_client.ApiClient`` deserializes ``List[Application]`` atomically -- a
single non-conforming app raises ``pydantic.ValidationError`` and aborts the
*entire* ``list_applications`` / ``list_assigned_applications_for_group`` call.
That takes down the whole app list (and any group-app audit that walks it),
rather than the one offending app.

This module patches the single deserialization choke point so a model that fails
strict validation is reconstructed leniently (validation bypassed via
``model_construct``) instead of taking down the response. The MCP server only
ever *reads* and summarizes apps, so lenient parsing on read is safe and the
returned object keeps the same concrete type and field shape as a healthy one.

The patch is idempotent and defensive: if the SDK internals change and the
expected hook point is absent, it logs a warning and leaves the SDK untouched.
"""

from __future__ import annotations

from loguru import logger

from okta_mcp_server.utils.serialization import describe_exception

# Name-mangled instance method on okta.api_client.ApiClient. It is the single
# point where every response model (including each element of a List[...]) is
# turned into a Pydantic object, so patching here covers all read paths.
_HOOK = "_ApiClient__deserialize_model"

_applied = False


def _fields_by_source_name(klass, data: dict) -> dict:
    """Map incoming (camelCase alias) keys to model field names.

    ``model_construct`` sets attributes by field name and does not honour
    aliases, so translate the Okta JSON keys (``signOnMode``) to the model's
    Python field names (``sign_on_mode``) first. Unknown keys are passed through
    unchanged and simply ignored by ``model_construct``.
    """
    mapping: dict[str, str] = {}
    for field_name, field in getattr(klass, "model_fields", {}).items():
        mapping[field_name] = field_name
        if field.alias:
            mapping[field.alias] = field_name
    return {mapping.get(key, key): value for key, value in data.items()}


def apply_okta_sdk_leniency() -> None:
    """Patch the Okta SDK to tolerate apps that violate its strict model schema.

    Safe to call more than once; only the first call has any effect.
    """
    global _applied
    if _applied:
        return

    try:
        import okta.models
        from okta.api_client import ApiClient
        from pydantic import ValidationError
    except Exception as exc:  # pragma: no cover - SDK layout changed
        logger.warning(f"okta_compat: Okta SDK not importable, leniency not applied: {exc}")
        return

    original = getattr(ApiClient, _HOOK, None)
    if original is None:
        logger.warning(
            f"okta_compat: {_HOOK} not found on ApiClient; SDK internals may have "
            "changed. Strict app deserialization left in place."
        )
        return

    def _lenient_deserialize_model(self, data, klass):
        try:
            return original(self, data, klass)
        except (ValidationError, ValueError) as exc:
            if not isinstance(data, dict):
                raise

            # Resolve the concrete subclass for discriminated unions
            # (Application -> SamlApplication / BrowserPluginApplication / ...).
            target = klass
            get_discriminator = getattr(klass, "get_discriminator_value", None)
            if get_discriminator is not None:
                resolved_name = get_discriminator(data)
                if resolved_name:
                    target = getattr(okta.models, resolved_name, klass)

            if not hasattr(target, "model_construct"):
                raise

            logger.debug(
                "okta_compat: relaxing strict validation for "
                f"{getattr(target, '__name__', target)} "
                f"(id={data.get('id')}): {describe_exception(exc)}"
            )
            return target.model_construct(**_fields_by_source_name(target, data))

    setattr(ApiClient, _HOOK, _lenient_deserialize_model)
    _applied = True
    logger.debug("okta_compat: applied lenient application deserialization patch")
