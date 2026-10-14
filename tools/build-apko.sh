#!/usr/bin/env bash
# Publish one glibc image (prod + dev) with apko and record the refs for the next steps.
#
#   IMAGE_NAMESPACE  ghcr.io/<owner>/nineline
#   SOURCE_DATE_EPOCH  the run time (apko uses it for `created`)
#   DATE_TAG         YYYY.MM.DD of the run
#   OUT              out/<name>
set -euo pipefail
name=${1:?image name}
: "${IMAGE_NAMESPACE:?}" "${SOURCE_DATE_EPOCH:?}" "${DATE_TAG:?}" "${OUT:?}"
root=$(pwd)
mkdir -p "$OUT/sbom-apko" "$OUT/sbom-apko-dev"

# apko resolves `include:` (dev.yaml -> image.yaml) against the working directory.
# It prints the published reference (with digest) on stdout and logs on stderr.
cd "images/$name"
prod=$(apko publish image.yaml "$IMAGE_NAMESPACE/$name:latest" \
         --arch x86_64,aarch64 --sbom-path "$root/$OUT/sbom-apko" 2>"$root/$OUT/apko-prod.log" | tail -1)
dev=$(apko publish dev.yaml "$IMAGE_NAMESPACE/$name:latest-dev" \
        --arch x86_64,aarch64 --sbom-path "$root/$OUT/sbom-apko-dev" 2>"$root/$OUT/apko-dev.log" | tail -1)
cd "$root"
[[ "$prod" == *@sha256:* && "$dev" == *@sha256:* ]] || { echo "apko did not return digests: prod='$prod' dev='$dev'"; exit 1; }

version_tag=""
case $name in
  nginx)  pkg=nginx-mainline ;;
  jre)    pkg=openjdk-21-jre ;;
  tomcat) pkg=tomcat-11.0-openjdk-21 ;;
  *)      pkg="" ;;
esac
if [[ -n "$pkg" ]]; then
  version_tag=$(python3 tools/factory.py version-tag --sbom "$OUT/sbom-apko/sbom-x86_64.spdx.json" --package "$pkg")
fi

{
  echo "PROD_REF=$prod"
  echo "DEV_REF=$dev"
  echo "VERSION_TAG=$version_tag"
  echo "DATE_TAG=$DATE_TAG"
  echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
} > "$OUT/refs.env"
echo "published $prod and $dev (version tag: ${version_tag:-none}, date tag: $DATE_TAG)"
