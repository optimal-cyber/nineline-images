# Local build kit

Builds the five Phase 0 images on a laptop the way the factory builds them, and
writes `scan_table.md` in the Appendix A format. CI
(`.github/workflows/factory.yml`) is the authority for every published number;
this kit is for a quick local check and for working on the image definitions.

1. Start Docker Desktop.
2. Install the tools once: `brew install trivy cosign syft apko`
3. From the repo root: `bash local-kit/build_and_scan.sh` (10 to 20 minutes the first time).
4. `local-kit/scan_table.md` is the table; `local-kit/out/` holds the evidence
   (SBOMs, signatures, verification output, Trivy JSON, `run.log`, upstream digests).

What it does

- Builds `base`, `nginx`, `jre` and `tomcat` from `images/<name>/image.yaml` with apko
  (x86_64 only, to keep the run short) and `ubi9-hardened` with Docker.
- Records whether each image contains a shell (`out/run.log`).
- Pushes to a throwaway local registry, signs each image digest with a local key,
  attaches SPDX and CycloneDX SBOM attestations, and verifies both. The key is
  generated on first run and gitignored; CI signs keyless, so this run is not
  evidence of signing, only that the images and attestations are well formed.
- Scans each NINELINE image and the upstream image FDIC named with the same Trivy
  version, pins the upstream images by digest, and writes `scan_table.md`.

If a build fails, the log is in `out/<name>.build.log`. The usual cause is a
Wolfi package rename; apko prints the name it could not find.
