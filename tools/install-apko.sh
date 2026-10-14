#!/usr/bin/env bash
# Install a pinned apko release on a Linux amd64 runner, checking the release checksum.
set -euo pipefail
version=${1:?apko version, e.g. 1.4.11}
asset="apko_${version}_linux_amd64.tar.gz"
base="https://github.com/chainguard-dev/apko/releases/download/v${version}"
curl -fsSLo "$asset" "$base/$asset"
curl -fsSLo checksums.txt "$base/checksums.txt"
grep " ${asset}\$" checksums.txt | sha256sum -c -
tar -xzf "$asset" "apko_${version}_linux_amd64/apko"
sudo install -m 0755 "apko_${version}_linux_amd64/apko" /usr/local/bin/apko
rm -rf "$asset" checksums.txt "apko_${version}_linux_amd64"
apko version
