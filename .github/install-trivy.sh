#!/usr/bin/env bash
# Install a pinned Trivy release, verified against a checksum committed here.
# Bumping Trivy means updating both values below, so a new binary can't arrive
# without a reviewed commit.
set -euo pipefail

TRIVY_VERSION="0.76.2"
TRIVY_SHA256="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf" # trivy_0.76.2_Linux-64bit.tar.gz

tarball="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$tarball" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tarball}"
echo "${TRIVY_SHA256}  $tmp/$tarball" | sha256sum --check --strict
sudo tar -xzf "$tmp/$tarball" -C /usr/local/bin trivy
trivy --version
