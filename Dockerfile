# Alpine base: python:3.13-slim (Debian 13) carried ~56 HIGH OS CVEs, most with
# no Debian fix. Alpine's OS layer has none, and every compiled dependency in
# uv.lock ships a musllinux cp313 wheel, so nothing is built from source.
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS build

# Install uv (0.11.31+ carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195)
COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Copy dependency files first (for better caching). Dependencies are installed
# from wheels only, so a missing musllinux wheel fails here instead of trying a
# source build in an image with no compiler.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project --no-build

COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e

LABEL Title="Okta MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

# The app runs from its own venv. The base image's pip (and the packages it
# vendors: urllib3, msgpack, requests, ...) is unused and is where the base
# image's remaining HIGH findings live, so remove it and its bundled wheel.
RUN python -m pip uninstall -y pip setuptools wheel || true; \
    rm -rf /usr/local/lib/python3.13/ensurepip/_bundled

# Create non-root user for security
RUN adduser -D -h /home/appuser -s /sbin/nologin appuser

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

# For Docker/Compose. Kubernetes ignores this and uses the chart's probes.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

# Run the server using the console script entry point
ENTRYPOINT ["okta-mcp-server"]
