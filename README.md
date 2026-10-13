# NINELINE Hardened Images

Image definitions and the build factory for **NINELINE Hardened Images**: minimal,
signed, continuously rebuilt container images with SBOMs, built from public
packages and published to `ghcr.io/optimal-cyber/nineline/<name>`.

This repository is public so that the images' signatures, SBOM attestations and
build provenance are recorded in the public Sigstore transparency log and anyone
can verify them. The service that evaluates these images (vulnerability findings,
VEX, dispositions, FedRAMP clocks, the catalog) is NINELINE itself.

## Images

| Name | Family | Contents | Runs as | Shell |
| --- | --- | --- | --- | --- |
| `base` | glibc (Wolfi, apko) | wolfi-baselayout, glibc, ca-certificates-bundle, tzdata | 65532 | none |
| `nginx` | glibc (Wolfi, apko) | base + nginx mainline, binds :80 as 65532 via `cap_net_bind_service` | 65532 | none |
| `jre` | glibc (Wolfi, apko) | base + OpenJDK 21 JRE; entrypoint `java` | 65532 | none |
| `tomcat` | glibc (Wolfi, apko) | base + Apache Tomcat 11 on OpenJDK 21; entrypoint starts `Bootstrap` with `java` directly | 65532 | none |
| `ubi9-hardened` | Red Hat compatible (UBI 9) | glibc, coreutils-single, ca-certificates from UBI 9 repositories only; setuid bits removed; bash removed after install | 65532 | none |

Every glibc image also has a `-dev` variant (`images/<name>/dev.yaml`: the
production image plus bash, busybox and apk-tools) for debugging and building.
Dev images are never the images that ship.

Package versions are whatever Wolfi and UBI publish at build time; the SBOM
attached to each digest is the record.

## Layout

```
images/<name>/image.yaml   apko definition of the production image
images/<name>/dev.yaml     `include: image.yaml` + the dev packages (apko resolves the
                           include against the working directory: run apko inside the folder)
images/ubi9-hardened/Dockerfile
local-kit/                 laptop build + Appendix A table (see local-kit/README.md)
.github/workflows/factory.yml   the factory (nightly, on push to images/, and on demand)
baseline.json              package counts and sizes the growth check compares against
```

## How the factory builds (summary; the workflow is the source of truth)

- apko publishes each glibc image for `x86_64` and `aarch64` as one index, with
  `SOURCE_DATE_EPOCH` set to the run time so `created` is the build time.
- `ubi9-hardened` is built with buildx for `linux/amd64` and `linux/arm64`.
- Every image digest is signed keyless with cosign (Sigstore Fulcio certificate for
  the workflow identity, recorded in Rekor), with SPDX and CycloneDX SBOM
  attestations (`cosign attest --type spdxjson|cyclonedx`), and SLSA v1.0 build
  provenance from `actions/attest-build-provenance` (Build Level 2).
- cosign is pinned to v2.5.x: signatures and attestations use the classic
  `.sig` / `.att` tag layout that registries and proxies (Harbor, JFrog) handle today.
- Each image and the upstream image it replaces are scanned with the same Trivy
  version; the JSON is an artifact of the run, as is `manifest.json` with every
  digest, attestation and upstream digest.

## Verify an image

```bash
cosign verify ghcr.io/optimal-cyber/nineline/base:latest \
  --certificate-identity "https://github.com/optimal-cyber/nineline-images/.github/workflows/factory.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation --type spdxjson ghcr.io/optimal-cyber/nineline/base:latest \
  --certificate-identity "https://github.com/optimal-cyber/nineline-images/.github/workflows/factory.yml@refs/heads/main" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r .payload | base64 -d | jq .predicate

gh attestation verify oci://ghcr.io/optimal-cyber/nineline/base:latest -R optimal-cyber/nineline-images
```

## Tags

`latest`, `latest-dev`, the Wolfi package version for `nginx`, `jre` and `tomcat`
(for example `1.31.6`), and a date tag (`2026.10.15`) for `base` and `ubi9-hardened`.

## Design notes (verified 2026-10-13)

- Wolfi's `nginx-mainline-config` listens on port 80. As uid 65532 that needs
  `cap_net_bind_service`, which Wolfi ships as a second nginx binary in
  `nginx-mainline-privileged-netbindservice`; apko installs both without conflict
  and the capability survives in the image layer (tested: HTTP 200 on :80 as 65532).
  nginx's prefix is `/var/lib/nginx`; its `tmp` and `logs` are owned by 65532 and
  the pid file is moved there because `/run` is not writable.
- `catalina.sh` is a shell script, so the shell-less tomcat image starts
  `org.apache.catalina.startup.Bootstrap` with `java` and the properties
  `catalina.sh` would set. `logs`, `temp`, `work`, `webapps` and `conf/Catalina`
  are owned by 65532; the rest of `conf/` stays root-owned.
- In UBI 9, `ca-certificates` requires `bash` for its install scripts. The shell is
  removed from the files and the RPM database (`rpm -e --nodeps bash`) after
  installation, so scanners see the packages that are there.
- apko writes SPDX SBOMs; the CycloneDX SBOM attached to each image comes from syft.
