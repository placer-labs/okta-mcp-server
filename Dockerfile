FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS build

# Install uv (0.11.31+ carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195)
COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

LABEL Title="Okta MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

# The app runs from its own venv; the base image's pip and setuptools are unused
RUN python -m pip uninstall -y pip setuptools wheel || true

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app
COPY --from=build --chown=appuser:appuser /app/.venv /app/.venv
USER appuser

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
# Use file-based keyring backend for Docker (no system keyring available)
ENV PYTHON_KEYRING_BACKEND=keyrings.alt.file.PlaintextKeyring
# Use streamable HTTP transport in Docker
ENV MCP_TRANSPORT=streamable-http

EXPOSE 8000

# Run the server using the console script entry point
ENTRYPOINT ["okta-mcp-server"]
