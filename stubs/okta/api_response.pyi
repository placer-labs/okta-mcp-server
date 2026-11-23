"""Stub for okta.api_response.ApiResponse — minimal surface used by the MCP."""

from typing import Any

class ApiResponse:
    status_code: int | None
    headers: dict[str, Any]
    data: Any
    raw_data: Any

    def __init__(self, **kwargs: Any) -> None: ...
