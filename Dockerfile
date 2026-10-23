FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39

LABEL Title="Okta MCP Server" \
      Description="Model Context Protocol server for Okta API integration" \
      Authors="Okta" \
      Licenses="Apache-2.0" \
      Version="1.0.0" \
      Maintainer="Okta"

# Install uv (0.11.31+ carries the quick-xml 0.41.0 fix for RUSTSEC-2026-0194/0195)
COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml uv.lock ./

COPY src ./src

# Copy README.md if it exists (needed by some builds)
COPY README.md ./

RUN uv sync --no-dev

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
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
