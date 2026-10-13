#!/usr/bin/env bash
# NINELINE local build kit: builds the five Phase 0 images on a laptop the way the
# factory workflow builds them, generates SBOMs, signs each image at the digest
# level with SBOM attestations (a throwaway local key; CI signs keyless), verifies
# them, scans them next to the upstream images with Trivy, and writes scan_table.md
# in the Appendix A format.
#
# CI (.github/workflows/factory.yml) is the authority for published numbers; this
# is for a quick local check and for working on the image definitions.
#
# Needs (macOS): Docker Desktop running, plus:  brew install trivy cosign syft apko
# Run:  bash local-kit/build_and_scan.sh   (from the repo root, or from local-kit/)
set -uo pipefail
cd "$(dirname "$0")" || exit 1
ROOT=$(cd .. && pwd)
KIT=$PWD
OUT=out; mkdir -p "$OUT"
LOG="$OUT/run.log"; : > "$LOG"
REG=localhost:5000
# apko stamps `created` with the newest package's build time unless told the
# build time; the factory sets this to the run time and so does this script.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(date +%s)}

for t in docker trivy cosign syft apko python3 curl; do
  command -v "$t" >/dev/null || { echo "Missing $t. Install with: brew install $t (Docker Desktop for docker)"; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "Start Docker Desktop first."; exit 1; }
{ echo "== tool versions"; docker --version; trivy --version | head -1; cosign version 2>/dev/null | grep -i gitversion; syft version 2>/dev/null | grep -i '^version'; apko version 2>/dev/null | grep -i '^version\|^gitversion' | head -1
  echo "== SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ))"; } >>"$LOG" 2>&1

# 1. The four glibc-family images with apko, and the Red Hat compatible base with Docker.
#    apko resolves `include:` (dev.yaml -> image.yaml) against the working directory,
#    so it runs inside each image's directory.
build_apko() {  # $1 name -> sets IMG_<name> to the loaded image name
  local n=$1 img=""
  echo "Building nineline/$n ..."
  mkdir -p "$OUT/$n-apko-sbom"
  if (cd "$ROOT/images/$n" && apko build image.yaml "nineline/$n:latest" "$KIT/$OUT/$n.tar" \
        --arch x86_64 --sbom-path "$KIT/$OUT/$n-apko-sbom") >"$OUT/$n.build.log" 2>&1; then
    img=$(docker load -i "$OUT/$n.tar" | sed -n 's/^Loaded image: //p' | tail -1)   # nineline/<n>:latest-amd64
    [[ -n "$img" ]] && echo "  loaded $img" || echo "  built, but docker load failed; see $OUT/$n.build.log"
  else
    echo "  BUILD FAILED, see $OUT/$n.build.log"
  fi
  printf -v "IMG_$n" '%s' "$img"
}
build_apko base; build_apko nginx; build_apko jre; build_apko tomcat

echo "Building nineline/ubi9-hardened ..."
IMG_ubi=""
if docker build --platform linux/amd64 -t nineline/ubi9-hardened:latest "$ROOT/images/ubi9-hardened" >"$OUT/ubi9-hardened.build.log" 2>&1; then
  IMG_ubi="nineline/ubi9-hardened:latest"; echo "  built $IMG_ubi"
else
  echo "  BUILD FAILED, see $OUT/ubi9-hardened.build.log"
fi

# Production images carry no shell. Recorded, not assumed.
echo "== shell check (files named sh or bash in each image)" >>"$LOG"
for n in base nginx jre tomcat ubi; do
  img=$(eval echo "\${IMG_$n:-}"); [[ -z "$img" ]] && continue
  cid=$(docker create --platform linux/amd64 "$img" true 2>/dev/null) || continue
  shells=$(docker export "$cid" | tar -t 2>/dev/null | grep -E '(^|/)(bin|sbin)/(ba)?sh$' | tr '\n' ' ')
  docker rm "$cid" >/dev/null 2>&1
  echo "  $img: ${shells:-no shell}" >>"$LOG"
done

# 2. Push to a throwaway local registry, sign each image digest, attach SBOM attestations, verify.
#    Local key, no transparency log: this run is not evidence of signing, the factory run is.
docker inspect nineline-registry >/dev/null 2>&1 || docker run -d -p 5000:5000 --name nineline-registry registry:2 >>"$LOG" 2>&1
sleep 2
[[ -f cosign.key ]] || COSIGN_PASSWORD="" cosign generate-key-pair >>"$LOG" 2>&1
OFF=(--tlog-upload=false)
cosign sign --help 2>&1 | grep -q -- '--use-signing-config' && OFF+=(--use-signing-config=false)
NET=(--allow-insecure-registry --allow-http-registry)
for n in base nginx jre tomcat ubi; do
  img=$(eval echo "\${IMG_$n:-}"); [[ -z "$img" ]] && continue
  syft "$img" -q -o spdx-json="$OUT/$n.spdx.json" -o cyclonedx-json="$OUT/$n.cdx.json" 2>>"$LOG"
  docker tag "$img" "$REG/nineline/$n:latest" && docker push -q "$REG/nineline/$n:latest" >>"$LOG" 2>&1
  ref=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$REG/nineline/$n:latest" 2>/dev/null | grep "^$REG/" | head -1)
  if [[ -z "$ref" ]]; then echo "  push failed for $n (see $LOG)"; continue; fi
  echo "$n digest: $ref" >>"$LOG"
  printf -v "REF_$n" '%s' "$ref"
  ok=1
  COSIGN_PASSWORD="" cosign sign --yes --key cosign.key "${OFF[@]}" "${NET[@]}" "$ref" >>"$LOG" 2>&1 || ok=0
  COSIGN_PASSWORD="" cosign attest --yes --key cosign.key "${OFF[@]}" "${NET[@]}" --type spdxjson --predicate "$OUT/$n.spdx.json" "$ref" >>"$LOG" 2>&1 || ok=0
  COSIGN_PASSWORD="" cosign attest --yes --key cosign.key "${OFF[@]}" "${NET[@]}" --type cyclonedx --predicate "$OUT/$n.cdx.json" "$ref" >>"$LOG" 2>&1 || ok=0
  cosign verify --key cosign.pub --insecure-ignore-tlog=true "${NET[@]}" "$ref" >"$OUT/$n.verify.json" 2>>"$LOG" || ok=0
  cosign verify-attestation --key cosign.pub --insecure-ignore-tlog=true "${NET[@]}" --type spdxjson "$ref" >"$OUT/$n.verify-attestation.json" 2>>"$LOG" || ok=0
  [[ $ok == 1 ]] && echo "  signed, attested and verified $ref" || echo "  signing or verification failed for $n (details in $LOG)"
done

# 3. Scan upstream and NINELINE images the same way, same day, same scanner.
trivy image --download-db-only >>"$LOG" 2>&1
TV=$(trivy --version | head -1)
scan() { trivy image --quiet --platform linux/amd64 --scanners vuln --list-all-pkgs --format json --output "$2" "$1" 2>>"$LOG"; }
csize() {  # $1 ref -> compressed pull size for linux/amd64: the sum of layer sizes in the registry manifest
  local extra=(); [[ $1 == "$REG/"* ]] && extra=(--insecure)
  docker manifest inspect --verbose "${extra[@]}" "$1" 2>>"$LOG" | python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: print(""); sys.exit()
items = d if isinstance(d, list) else [d]
pick = next((i for i in items if ((i.get("Descriptor") or {}).get("platform") or {}).get("architecture") == "amd64"), items[0])
m = pick.get("SchemaV2Manifest") or pick.get("OCIManifest") or {}
print(sum(l.get("size", 0) for l in m.get("layers") or []))'
}
stats() {  # $1 ref, $2 json -> "C/H/M/L|packages|MB"
  python3 - "$2" "$(csize "$1")" <<'PY'
import json, sys
try: d = json.load(open(sys.argv[1]))
except Exception: print("scan failed|n/a|n/a"); sys.exit()
seen, pk, c = set(), set(), {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
for r in d.get("Results") or []:
    for p in r.get("Packages") or []: pk.add((p.get("Name"), p.get("Version")))
    for v in r.get("Vulnerabilities") or []:
        k = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
        if k in seen: continue
        seen.add(k)
        if v.get("Severity") in c: c[v["Severity"]] += 1
size = int(sys.argv[2] or 0)
sz = f"{size/1e6:.1f}" if size else "n/a"
print(f'{c["CRITICAL"]}/{c["HIGH"]}/{c["MEDIUM"]}/{c["LOW"]}|{len(pk)}|{sz}')
PY
}
ROWS=(
  "Alpine|alpine:latest|base|base (glibc)"
  "Red Hat OS|registry.access.redhat.com/ubi9/ubi:latest|ubi|ubi9-hardened"
  "NGINX|nginx:latest|nginx|nginx"
  "Tomcat|tomcat:latest|tomcat|tomcat (Java 21)"
  "Spring Boot (JRE base)|eclipse-temurin:21-jre|jre|jre (Java 21)"
)
echo "Scanning..."
: > "$OUT/upstream-digests.txt"
{
  echo "| FDIC test image | Upstream image | NINELINE image | CVEs C/H/M/L, upstream then NINELINE | Packages, upstream then NINELINE | Size MB, upstream then NINELINE |"
  echo "| --- | --- | --- | --- | --- | --- |"
  for row in "${ROWS[@]}"; do
    IFS='|' read -r label up key shown <<< "$row"
    docker pull -q --platform linux/amd64 "$up" >>"$LOG" 2>&1
    d=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$up" 2>/dev/null | head -1)
    echo "${d:-$up (Docker recorded no RepoDigest for the local copy)}" >>"$OUT/upstream-digests.txt"
    fu="$OUT/upstream-$key.json"; scan "$up" "$fu"
    IFS='|' read -r cu pu su <<< "$(stats "$up" "$fu")"
    ref=$(eval echo "\${REF_$key:-}")
    if [[ -n "$ref" ]]; then
      fn="$OUT/nineline-$key.json"; scan "$ref" "$fn"
      IFS='|' read -r cn pn sn <<< "$(stats "$ref" "$fn")"
    else cn="build failed"; pn="n/a"; sn="n/a"; fi
    echo "| $label | $up | $shown | $cu then $cn | $pu then $pn | $su then $sn |"
  done
  echo
  echo "Scanner: $TV, linux/amd64, scanned $(date -u +%Y-%m-%dT%H:%MZ). Sizes are the compressed pull size (sum of layer sizes in the registry manifest). Upstream images pinned by digest in out/upstream-digests.txt. SBOMs, signatures, verification output and full JSON results are in out/."
} | tee scan_table.md
echo
echo "Done. scan_table.md is the table; keep out/ as evidence."
echo "To remove the local test registry later: docker rm -f nineline-registry"
