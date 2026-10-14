#!/usr/bin/env bash
# For one published image: sign every digest keyless, attach SPDX and CycloneDX SBOM
# attestations per platform, scan every platform and the upstream image with Trivy,
# add the version and date tags, and verify the signature the way a customer will.
#
# Reads $OUT/refs.env (PROD_REF, DEV_REF, VERSION_TAG, DATE_TAG) and appends the
# upstream digest, the certificate identity and the verification result to it.
# Writes $OUT/<variant>-platforms.txt ("<arch> <digest>" per line) for factory.py.
set -euo pipefail
name=${1:?image name}
: "${IMAGE_NAMESPACE:?}" "${OUT:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_REF:?}"
# shellcheck source=/dev/null
source "$OUT/refs.env"
identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/factory.yml@${GITHUB_REF}"
issuer="https://token.actions.githubusercontent.com"

platforms() {  # $1 ref with digest, $2 manifest json -> "<arch> <digest>" lines
  python3 - "$1" "$2" <<'PY'
import json, subprocess, sys
ref, path = sys.argv[1], sys.argv[2]
doc = json.load(open(path))
if "manifests" in doc:                      # an index: one line per platform manifest
    for m in doc["manifests"]:
        arch = (m.get("platform") or {}).get("architecture")
        if arch and arch != "unknown":
            print(arch, m["digest"])
else:                                        # a single image: its own digest, arch from the config
    cfg = json.loads(subprocess.check_output(["crane", "config", ref]))
    print(cfg["architecture"], ref.split("@")[1])
PY
}

process() {  # $1 ref with digest, $2 variant (prod|dev)
  local ref=$1 variant=$2 image arch d aref
  image=${ref%@*}
  echo "== $variant: $ref"
  # The index (if any) and every platform manifest it references.
  cosign sign --yes --recursive "$ref"
  crane manifest "$ref" > "$OUT/$variant-index.json"
  platforms "$ref" "$OUT/$variant-index.json" > "$OUT/$variant-platforms.txt"
  while read -r arch d; do
    aref="$image@$d"
    crane manifest "$aref" > "$OUT/$variant-$arch-manifest.json"
    crane config "$aref" > "$OUT/$variant-$arch-config.json"
    syft "registry:$aref" --platform "linux/$arch" -q \
      -o "spdx-json=$OUT/$variant-$arch.spdx.json" -o "cyclonedx-json=$OUT/$variant-$arch.cdx.json"
    cosign attest --yes --type spdxjson --predicate "$OUT/$variant-$arch.spdx.json" "$aref"
    cosign attest --yes --type cyclonedx --predicate "$OUT/$variant-$arch.cdx.json" "$aref"
    trivy image --quiet --platform "linux/$arch" --scanners vuln --list-all-pkgs \
      --format json --output "$OUT/$variant-$arch.trivy.json" "$aref"
  done < "$OUT/$variant-platforms.txt"
}

process "$PROD_REF" prod
if [[ -n "${DEV_REF:-}" ]]; then process "$DEV_REF" dev; fi

for t in ${VERSION_TAG:-} ${DATE_TAG:-}; do
  crane tag "$PROD_REF" "$t"
done

# The upstream image FDIC named, pinned by its linux/amd64 digest at scan time.
case $name in
  base)          upstream=docker.io/library/alpine:latest ;;
  ubi9-hardened) upstream=registry.access.redhat.com/ubi9/ubi:latest ;;
  nginx)         upstream=docker.io/library/nginx:latest ;;
  tomcat)        upstream=docker.io/library/tomcat:latest ;;
  jre)           upstream=docker.io/library/eclipse-temurin:21-jre ;;
  *) echo "no upstream mapping for $name"; exit 1 ;;
esac
updigest=$(crane digest --platform linux/amd64 "$upstream")
upref="${upstream%:*}@$updigest"
crane manifest "$upref" > "$OUT/upstream-amd64-manifest.json"
trivy image --quiet --platform linux/amd64 --scanners vuln --list-all-pkgs \
  --format json --output "$OUT/upstream-amd64.trivy.json" "$upref"

# Verify exactly as the README tells a customer to; the run fails if this does not pass.
verified=0
cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$PROD_REF" \
  > "$OUT/prod-verify.json" && verified=1
first=$(head -1 "$OUT/prod-platforms.txt" | cut -d' ' -f2)
cosign verify-attestation --type spdxjson --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
  "${PROD_REF%@*}@$first" > "$OUT/prod-verify-attestation.json" || verified=0

{
  echo "UPSTREAM=$upstream"
  echo "UPSTREAM_DIGEST=$updigest"
  echo "CERT_IDENTITY=$identity"
  echo "VERIFIED=$verified"
} >> "$OUT/refs.env"
[[ $verified == 1 ]] || { echo "signature or attestation verification failed for $PROD_REF"; exit 1; }
echo "signed, attested, scanned and verified $PROD_REF"
