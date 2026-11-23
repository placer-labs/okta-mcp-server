"""Type stubs for okta.pagination — covers PaginationHelper + paginate_all."""

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

class PaginationHelper:
    @staticmethod
    def extract_next_cursor(headers: dict[str, Any]) -> str | None: ...
    @staticmethod
    def has_next_page(headers: dict[str, Any]) -> bool: ...

def paginate_all(
    api_method: Callable[..., Awaitable[tuple[Any, Any, Any]]],
    limit: int = ...,
    max_pages: int | None = ...,
    **kwargs: Any,
) -> AsyncIterator[Any]: ...
def paginate_pages(
    api_method: Callable[..., Awaitable[tuple[Any, Any, Any]]],
    limit: int = ...,
    max_pages: int | None = ...,
    **kwargs: Any,
) -> AsyncIterator[list[Any]]: ...
