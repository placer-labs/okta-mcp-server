# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""JSON-response serialization for tools ported from upstream.

:func:`to_jsonable` flattens Okta SDK models, ``ApiResponse`` transport objects
and enums into JSON-native trees. :func:`json_response` applies it to a tool's
return value and turns the upstream error conventions (an ``{"error": ...}``
dict, or an uncaught exception) into ``ToolError`` so failures reach the client
as ``isError=True``, the same way the fork's own tools report them.
"""

import functools
import inspect
from enum import Enum
from typing import Any, Callable

from fastmcp.exceptions import ToolError
from loguru import logger
from pydantic import ValidationError

#: Maximum number of characters from str(exc) preserved in a ToolError message.
_ERROR_MESSAGE_LIMIT = 1024

#: Safety bound on recursion depth.  Okta payloads nest no deeper than ~10 in
#: practice; this guard exists only to short-circuit accidental cycles that
#: slip past the standard ``id`` check below.
_MAX_DEPTH = 64


# ---------------------------------------------------------------------------
# Core serializer
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Convert ``obj`` into a JSON-native tree.

    The output is restricted to ``dict | list | str | int | float | bool | None``
    so that ``json.dumps`` cannot fail on the result.  Conversion rules, in
    priority order:

    1. JSON-native scalars are returned as-is.
    2. ``Enum`` values are unwrapped to ``.value``.
    3. Pydantic v2 models are flattened via
       ``model_dump(by_alias=True, exclude_none=True, mode="json")`` so that
       camelCase keys, datetime → RFC 3339 strings, and ``UUID`` → string
       conversions are applied at the source.
    4. Okta SDK v2 models exposing ``to_dict()`` are flattened via that method.
    5. ``OktaAPIResponse`` (and any class whose name ends with ``ApiResponse``
       and that carries a ``headers`` attribute) is dropped to ``None``; the
       transport object is never useful to MCP callers.
    6. ``dict`` / ``list`` / ``tuple`` / ``set`` / ``frozenset`` are recursed
       element-wise.
    7. Objects exposing ``__dict__`` are flattened via ``vars(obj)`` and recursed.
    8. Anything else falls through to ``str(obj)`` and is logged at DEBUG so
       unexpected types surface during development.

    Types not explicitly handled (``bytes``, ``bytearray``, ``memoryview``,
    ``decimal.Decimal``, ``pathlib.Path``, ``datetime`` at the top level,
    etc.) fall through rule 8 to ``str(obj)`` — lossy but guaranteed
    JSON-serialisable.  Add an explicit branch here if a tool ever needs one
    of those types round-tripped losslessly.

    Args:
        obj: Any Python value coming back from a tool body.

    Returns:
        A JSON-native tree suitable for ``json.dumps``.
    """
    return _to_jsonable(obj, depth=0, seen=set())


def _to_jsonable(obj: Any, depth: int, seen: set) -> Any:
    """Recursive worker for :func:`to_jsonable`.

    ``seen`` tracks ``id(obj)`` for container objects so self-referential
    structures are short-circuited rather than recursed indefinitely.
    """
    if depth > _MAX_DEPTH:
        logger.debug(f"to_jsonable: max depth {_MAX_DEPTH} exceeded for {type(obj).__name__}")
        return str(obj)

    # 1. Enum -> .value (recurse so IntEnum / StrEnum / (str, Enum) mixins stay
    #    correct).  Must precede the scalar passthrough below because
    #    ``(str, Enum)`` classes (e.g. the Okta SDK's ``ApplicationSignOnMode``)
    #    satisfy ``isinstance(x, str)`` yet still carry the enum ``__str__`` /
    #    ``__repr__`` that leak Python object descriptions to any consumer
    #    that does not use ``json.dumps``' str-subclass fast path.
    if isinstance(obj, Enum):
        return _to_jsonable(obj.value, depth + 1, seen)

    # 2. JSON-native scalars
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # 3. Transport objects — drop before model_dump branches, since
    #    OktaAPIResponse exposes neither model_dump nor to_dict.
    if _is_transport_response(obj):
        return None

    # 4. Pydantic v2 model.  We accept the result only if it is dict/list-shaped;
    #    otherwise the attribute is a coincidence (e.g. an auto-generated Mock)
    #    and we fall through to the next strategy rather than recursing on
    #    another opaque object.
    model_dump = getattr(obj, "model_dump", None)
    if callable(model_dump):
        try:
            dumped = model_dump(by_alias=True, exclude_none=True, mode="json")
        except Exception as exc:
            logger.warning(f"to_jsonable: model_dump failed on {type(obj).__name__}: {exc}")
            raise
        if isinstance(dumped, (dict, list)):
            return _to_jsonable(dumped, depth + 1, seen)

    # 5. Okta SDK v2 model with to_dict().  Same dict/list-shape guard as above.
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            dumped = to_dict()
        except Exception as exc:
            logger.warning(f"to_jsonable: to_dict failed on {type(obj).__name__}: {exc}")
            raise
        if isinstance(dumped, (dict, list)):
            return _to_jsonable(dumped, depth + 1, seen)

    # 6. Defensive short-circuit for unittest.mock objects: every attribute
    #    access lazily mutates their ``__dict__``, which both poisons the
    #    ``vars()`` fallback ("dictionary changed size during iteration") and
    #    makes any attribute look callable.  Tools never legitimately return
    #    Mocks in production; emitting ``str(obj)`` keeps tests deterministic.
    #    We run this check *after* the model_dump / to_dict branches above so a
    #    caller that explicitly configures ``mock.to_dict.return_value`` still
    #    gets the configured dict flattened by the normal path.
    if type(obj).__module__ == "unittest.mock":
        return str(obj)

    # 7. Containers (cycle-guarded)
    obj_id = id(obj)
    if isinstance(obj, dict):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return {str(k): _to_jsonable(v, depth + 1, seen) for k, v in obj.items()}
        finally:
            seen.discard(obj_id)

    if isinstance(obj, (list, tuple, set, frozenset)):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return [_to_jsonable(v, depth + 1, seen) for v in obj]
        finally:
            seen.discard(obj_id)

    # 8. Plain object with attributes
    if hasattr(obj, "__dict__"):
        if obj_id in seen:
            return None
        seen.add(obj_id)
        try:
            return _to_jsonable(vars(obj), depth + 1, seen)
        finally:
            seen.discard(obj_id)

    # 9. Last resort
    logger.debug(f"to_jsonable: falling back to str() for {type(obj).__name__}")
    return str(obj)


def _is_transport_response(obj: Any) -> bool:
    """Return True if ``obj`` is an Okta SDK transport response.

    Covers Okta Python SDK v2 (``OktaAPIResponse``) and the v3 duck-typed
    ``ApiResponse`` family.  Detection is intentionally narrow: the class name
    must end with ``APIResponse`` / ``ApiResponse`` *and* the object must
    expose a ``headers`` or ``has_next`` attribute, so we never drop a
    domain model that happens to share a suffix.
    """
    cls_name = type(obj).__name__
    if not (cls_name.endswith("APIResponse") or cls_name.endswith("ApiResponse")):
        return False
    return hasattr(obj, "headers") or hasattr(obj, "has_next")


# ---------------------------------------------------------------------------
# None-body guard
# ---------------------------------------------------------------------------


def none_body_error(tool_name: str, action: str, hint: str) -> dict:
    """Build the ``{"error": ...}`` dict for the Okta SDK's ``(None, response,
    None)`` quirk — a nominally successful call whose result payload is
    ``None``.

    Every ``get_*``/``create_*``/``update_*``/``replace_*`` tool that unpacks
    an SDK 3-tuple should call this when the result is ``None`` despite
    ``err`` being falsy, instead of silently returning ``None``/``null`` to
    the MCP caller. Logs a warning and builds the caller-facing message in
    one call so call sites don't repeat the same six lines.

    Args:
        tool_name: The tool function's own name, for the log line.
        action: What the tool was doing, e.g. ``f"retrieving brand {brand_id!r}"``.
        hint: What the caller should do next, e.g. ``"Verify the ID with list_brands()."``.

    Returns:
        ``{"error": "Okta returned an empty response while <action>. <hint>"}``
    """
    logger.warning(f"{tool_name} returned no body despite success status ({action}).")
    return {"error": f"Okta returned an empty response while {action}. {hint}"}


# ---------------------------------------------------------------------------
# Exception messages
# ---------------------------------------------------------------------------


def describe_exception(exc: BaseException) -> str:
    """``str(exc)``, except a pydantic ``ValidationError`` reports only field locations and error types.

    Its default message echoes the rejected input, which for tool arguments can be
    client secrets, private keys or user profile values.
    """
    if isinstance(exc, ValidationError):
        details = "; ".join(
            f"{'.'.join(map(str, err['loc'])) or '<root>'}: {err['type']}"
            + (f" (expected {err['ctx']['expected']})" if "expected" in err.get("ctx", {}) else "")
            for err in exc.errors(include_input=False, include_url=False)
        )
        return f"{exc.error_count()} validation error(s) for {exc.title}: {details}"
    return str(exc)


def okta_tool_error(err: Any, scope: str, action: str, fallback: str | None = None) -> ToolError:
    """Build a ToolError for an SDK error or response, with a missing-scope hint on 401/403."""
    status = getattr(err, "status", None) or getattr(err, "status_code", None)
    if status in (401, 403, "401", "403"):
        return ToolError(
            f"Authorization error (HTTP {status}) while {action}: the OAuth client is missing the '{scope}' scope. "
            "Grant it to the Okta OIDC app, make sure OKTA_SCOPES requests it, and re-authenticate before retrying."
        )
    return ToolError(fallback or f"Okta API error: {err}")


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------


def _raise_if_error(result: Any) -> None:
    if isinstance(result, dict) and "error" in result:
        error = result["error"]
        raise ToolError(error if isinstance(error, str) else str(to_jsonable(error)))


def json_response(fn: Callable) -> Callable:
    """Serialize ``fn``'s return value through :func:`to_jsonable`.

    A returned ``{"error": ...}`` dict or an exception other than ``ToolError``
    is re-raised as ``ToolError``. Place it innermost, directly above ``async def``.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            try:
                result = await fn(*args, **kwargs)
                _raise_if_error(result)
                return to_jsonable(result)
            except ToolError:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {describe_exception(exc)[:_ERROR_MESSAGE_LIMIT]}"
                logger.error(f"[json_response] {getattr(fn, '__name__', 'tool')} failed: {message}")
                raise ToolError(message) from exc

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
            _raise_if_error(result)
            return to_jsonable(result)
        except ToolError:
            raise
        except Exception as exc:
            message = f"{type(exc).__name__}: {describe_exception(exc)[:_ERROR_MESSAGE_LIMIT]}"
            logger.error(f"[json_response] {getattr(fn, '__name__', 'tool')} failed: {message}")
            raise ToolError(message) from exc

    return sync_wrapper
