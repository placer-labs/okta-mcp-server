# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for :mod:`okta_mcp_server.utils.serialization`.

Coverage focuses on the boundary contracts that justified the rewrite:

* Pydantic v2 models, plain dicts, lists, tuples, sets, and nested mixes all
  round-trip through ``json.dumps``.
* ``Enum`` values are unwrapped to their ``.value``.
* ``datetime`` values are emitted as RFC 3339 strings.
* ``OktaAPIResponse`` (and v3 ``ApiResponse`` look-alikes) are dropped.
* Self-referential structures do not blow the stack.
* The decorator preserves ``__name__`` / ``__doc__`` and raises ``ToolError``
  for error dicts, tool exceptions and :func:`to_jsonable` failures.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import ClassVar

import okta.models as okta_models
import pytest
from fastmcp.exceptions import ToolError
from okta.models.application_sign_on_mode import ApplicationSignOnMode

from okta_mcp_server.utils.serialization import (
    json_response,
    none_body_error,
    to_jsonable,
)

# ---------------------------------------------------------------------------
# to_jsonable: scalars and enums
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, True, False, 0, 1, -3, 1.5, "", "hello"])
def test_scalars_pass_through(value):
    assert to_jsonable(value) == value


def test_enum_unwrapped_to_value():
    class Color(Enum):
        RED = "red"
        BLUE = "blue"

    assert to_jsonable(Color.RED) == "red"
    assert to_jsonable([Color.RED, Color.BLUE]) == ["red", "blue"]


def test_str_enum_mixin_unwrapped_to_value():
    """``(str, Enum)`` mixins (e.g. Okta's ``ApplicationSignOnMode``) must be
    unwrapped to their raw ``.value`` instead of leaking through the scalar
    passthrough.  Historically the scalar branch ran first, which let the
    enum object survive: any non-``json`` consumer (f-string, ``logger.info``)
    then rendered the Python repr ``<Color.RED: 'red'>`` — the exact bug
    described in issue #14.
    """

    class Color(str, Enum):
        RED = "red"
        BLUE = "blue"

    result = to_jsonable(Color.RED)
    assert result == "red"
    # Critical: the returned value must NOT still be the enum instance,
    # otherwise ``str(result)`` would still emit ``<Color.RED: 'red'>``.
    assert type(result) is str
    assert not isinstance(result, Color)

    # Nested inside a container round-trips through ``json.dumps`` cleanly.
    payload = {"mode": Color.BLUE, "modes": [Color.RED, Color.BLUE]}
    assert to_jsonable(payload) == {"mode": "blue", "modes": ["red", "blue"]}
    assert json.dumps(to_jsonable(payload)) == '{"mode": "blue", "modes": ["red", "blue"]}'


def test_int_enum_mixin_unwrapped_to_value():
    """``(int, Enum)`` mixins are unwrapped for the same reason as ``(str, Enum)``."""

    class Priority(int, Enum):
        LOW = 1
        HIGH = 2

    result = to_jsonable(Priority.HIGH)
    assert result == 2
    assert type(result) is int
    assert not isinstance(result, Priority)


# ---------------------------------------------------------------------------
# to_jsonable: containers
# ---------------------------------------------------------------------------


def test_dict_keys_coerced_to_str():
    result = to_jsonable({1: "a", "k": 2})
    assert result == {"1": "a", "k": 2}


def test_tuple_becomes_list():
    assert to_jsonable((1, 2, 3)) == [1, 2, 3]


def test_set_becomes_list():
    result = to_jsonable({1, 2, 3})
    assert isinstance(result, list)
    assert sorted(result) == [1, 2, 3]


def test_nested_structure_round_trips():
    payload = {
        "items": [{"id": "u1", "tags": ("a", "b")}, {"id": "u2", "tags": set()}],
        "meta": {"count": 2},
    }
    normalized = to_jsonable(payload)
    json.dumps(normalized)  # must not raise
    assert normalized["items"][0]["tags"] == ["a", "b"]


# ---------------------------------------------------------------------------
# to_jsonable: Pydantic v2 (Okta SDK) models
# ---------------------------------------------------------------------------


def test_pydantic_v2_model_is_flattened():
    app = okta_models.Application.model_construct(label="hello", sign_on_mode=ApplicationSignOnMode.SAML_2_0)
    result = to_jsonable(app)

    assert isinstance(result, dict)
    assert result.get("label") == "hello"
    # The output must not contain a Python repr like "<Application object at 0x...>".
    assert not re.search(r"<.+ object at 0x[0-9a-f]+>", json.dumps(result))


def test_list_of_models_round_trips():
    apps = [
        okta_models.Application.model_construct(label="a", sign_on_mode=ApplicationSignOnMode.SAML_2_0),
        okta_models.Application.model_construct(label="b", sign_on_mode=ApplicationSignOnMode.OPENID_CONNECT),
    ]
    result = to_jsonable(apps)

    assert isinstance(result, list)
    assert {item["label"] for item in result} == {"a", "b"}
    json.dumps(result)


# ---------------------------------------------------------------------------
# to_jsonable: datetime (RFC 3339 via Pydantic mode="json")
# ---------------------------------------------------------------------------


def test_datetime_in_pydantic_model_serialized_rfc3339():
    from pydantic import BaseModel

    class Stamped(BaseModel):
        when: datetime

    model = Stamped(when=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    result = to_jsonable(model)

    assert result["when"] == "2024-01-02T03:04:05Z"


def test_custom_pages_serialize_emits_rfc3339_datetime():
    """PR #90 review round 4: ``custom_pages._serialize`` must set
    ``mode='json'`` so nested datetimes survive as RFC 3339 strings when the
    payload flows through the outer ``@json_response`` boundary.  Without
    ``mode='json'``, ``model_dump`` returns a raw ``datetime`` and
    ``to_jsonable`` would fall through to ``str(datetime)`` producing
    ``"2024-01-02 03:04:05+00:00"`` (space separator) instead of the
    ``"2024-01-02T03:04:05Z"`` required by RFC 3339.
    """
    from pydantic import BaseModel

    from okta_mcp_server.tools.customization.custom_pages.custom_pages import (
        _serialize,
    )

    class PageWithTimestamp(BaseModel):
        when: datetime

    model = PageWithTimestamp(when=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    serialized = _serialize(model)
    # After the local _serialize, the outer boundary runs to_jsonable — but
    # since serialized is already a plain dict, we can assert directly.
    assert serialized["when"] == "2024-01-02T03:04:05Z", (
        "custom_pages._serialize dropped mode='json' — datetime is no longer RFC 3339."
    )


# ---------------------------------------------------------------------------
# to_jsonable: transport object suppression
# ---------------------------------------------------------------------------


def test_okta_api_response_is_dropped():
    class OktaAPIResponse:  # mimics okta.api_response.OktaAPIResponse shape
        headers: ClassVar[dict] = {"x-okta-request-id": "abc"}

        def has_next(self) -> bool:
            return False

    assert to_jsonable(OktaAPIResponse()) is None


def test_v3_apiresponse_is_dropped():
    class ApiResponse:  # mimics SDK v3 duck-typed shape
        headers: ClassVar[dict] = {"Link": "..."}

    assert to_jsonable(ApiResponse()) is None


def test_response_lookalike_without_headers_is_not_dropped():
    """Class-name suffix alone must not cause a drop — protect domain models."""

    class CustomApiResponse:
        def __init__(self):
            self.label = "ok"

    result = to_jsonable(CustomApiResponse())
    assert result == {"label": "ok"}


# ---------------------------------------------------------------------------
# to_jsonable: safety guards
# ---------------------------------------------------------------------------


def test_self_referential_dict_does_not_recurse_forever():
    payload: dict = {"name": "loop"}
    payload["self"] = payload

    result = to_jsonable(payload)

    assert result["name"] == "loop"
    assert result["self"] is None  # cycle short-circuit


def test_unknown_object_falls_back_to_str():
    class Opaque:
        __slots__ = ()  # no __dict__, no model_dump, no to_dict

        def __str__(self) -> str:
            return "opaque-token"

    assert to_jsonable(Opaque()) == "opaque-token"


def test_unconfigured_mock_is_short_circuited_to_str():
    """``MagicMock`` exposes every attribute, including ``model_dump`` /
    ``to_dict`` / ``__dict__``; left unguarded the serializer would either
    recurse on opaque child mocks or trip ``RuntimeError: dictionary changed
    size during iteration`` while iterating ``vars(mock)``.  The defensive
    ``unittest.mock`` check must intercept the object and emit ``str(mock)``.
    """
    from unittest.mock import MagicMock

    result = to_jsonable(MagicMock(name="opaque"))

    assert isinstance(result, str)
    assert "Mock" in result


def test_mock_with_configured_to_dict_is_flattened():
    """A Mock whose ``to_dict`` is explicitly configured to return a real dict
    must take the SDK-v2 branch *before* the mock short-circuit fires, so test
    fixtures that simulate the Okta SDK contract keep working.
    """
    from unittest.mock import MagicMock

    mock_model = MagicMock()
    mock_model.to_dict.return_value = {"id": "abc", "status": "ACTIVE"}

    result = to_jsonable(mock_model)

    assert result == {"id": "abc", "status": "ACTIVE"}


def test_non_dict_model_dump_result_is_rejected():
    """``model_dump`` returning a non-dict / non-list value (e.g. another
    opaque object) must not be trusted — the serializer should fall through
    to subsequent strategies rather than recursing on whatever was returned.
    """

    class WeirdModel:
        def model_dump(self, **_kwargs):
            return object()  # not a dict, not a list, not a scalar

        def to_dict(self):
            return {"fallback": True}

    assert to_jsonable(WeirdModel()) == {"fallback": True}


def test_idempotent_on_already_jsonable_tree():
    payload = {"a": 1, "b": [True, None, "x"], "c": {"d": 2.5}}
    assert to_jsonable(to_jsonable(payload)) == payload


# ---------------------------------------------------------------------------
# @json_response decorator
# ---------------------------------------------------------------------------


def test_decorator_preserves_metadata_async():
    @json_response
    async def my_tool() -> dict:  # ruff: ignore[unused-async]
        """Docstring of my_tool."""
        return {"ok": True}

    assert my_tool.__name__ == "my_tool"
    assert my_tool.__doc__ == "Docstring of my_tool."


def test_decorator_serializes_async_result():
    @json_response
    async def echo_app():  # ruff: ignore[unused-async]
        return okta_models.Application.model_construct(label="hi", sign_on_mode=ApplicationSignOnMode.SAML_2_0)

    result = asyncio.run(echo_app())

    assert isinstance(result, dict)
    assert result["label"] == "hi"
    json.dumps(result)


def test_decorator_raises_tool_error_when_serializer_raises(monkeypatch):
    @json_response
    async def will_break():  # ruff: ignore[unused-async]
        return object()

    from okta_mcp_server.utils import serialization as ser

    def _raise(*_args, **_kwargs):
        raise RuntimeError("induced failure")

    monkeypatch.setattr(ser, "to_jsonable", _raise)

    with pytest.raises(ToolError, match="RuntimeError: induced failure"):
        asyncio.run(will_break())


def test_decorator_raises_tool_error_when_tool_body_raises():
    @json_response
    async def raises_before_any_return():  # ruff: ignore[unused-async]
        raise AttributeError("'NoneType' object has no attribute 'okta_auth_manager'")

    with pytest.raises(ToolError, match="AttributeError"):
        asyncio.run(raises_before_any_return())


def test_decorator_raises_tool_error_when_sync_tool_body_raises():
    @json_response
    def raises_immediately():
        raise ValueError("bad input")

    with pytest.raises(ToolError, match="ValueError: bad input"):
        raises_immediately()


def test_decorator_truncates_long_exception_messages():
    @json_response
    def raises_long():
        raise RuntimeError("x" * 5000)

    with pytest.raises(ToolError) as exc_info:
        raises_long()

    assert len(str(exc_info.value)) <= len("RuntimeError: ") + 1024


def test_decorator_passes_tool_error_through_unchanged():
    @json_response
    def raises_tool_error():
        raise ToolError("Okta API error: nope")

    with pytest.raises(ToolError, match=r"^Okta API error: nope$"):
        raises_tool_error()


def test_decorator_raises_tool_error_for_error_dict():
    @json_response
    async def returns_error():  # ruff: ignore[unused-async]
        return {"error": "Brand not found"}

    with pytest.raises(ToolError, match="Brand not found"):
        asyncio.run(returns_error())


def test_none_body_error_is_raised_as_tool_error():
    @json_response
    def empty_body():
        return none_body_error("get_brand", "retrieving brand 'b1'", "Verify the ID with list_brands().")

    with pytest.raises(ToolError, match=r"empty response while retrieving brand 'b1'\. Verify the ID"):
        empty_body()


def test_decorator_supports_sync_functions():
    @json_response
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5
