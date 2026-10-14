#!/usr/bin/env python3
"""Helpers the factory workflow calls between tool invocations. Standard library only.

    factory.py version-tag --sbom <apko spdx json> --package <name>
        The Wolfi version of a package without its release suffix (1.31.6-r3 -> 1.31.6).

    factory.py entry --name <image> --out-dir out/<image> --namespace ghcr.io/... \
        --run-url <url> [--provenance-url <url>] [--ubi-arch-fallback]
        One manifest entry per published variant (prod, dev), built from the files
        the shell steps left in out-dir: refs.env, <variant>-platforms.txt,
        <variant>-<arch>-manifest.json, <variant>-<arch>-config.json,
        <variant>-<arch>.trivy.json, upstream-amd64-manifest.json,
        upstream-amd64.trivy.json. Writes out-dir/entries.json.

    factory.py growth --baseline baseline.json --entries out/<image>/entries.json
        Fails (exit 1) when a prod image's package count or compressed size grew more
        than 10% over the baseline. No baseline for the image: reports it, exit 0.

    factory.py merge --out manifest.json --baseline-out baseline-candidate.json \
        --run-url <url> --rules-note "..." out/*/entries.json
        The run's manifest, and a baseline file built from this run's prod images.

Every number here is read from a scanner or registry output; nothing is estimated.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

FAMILY = {"base": "glibc", "nginx": "glibc", "jre": "glibc", "tomcat": "glibc", "ubi9-hardened": "redhat"}
#: The upstream image each NINELINE image is compared with (FDIC's five test images).
UPSTREAM = {
    "base": "docker.io/library/alpine:latest",
    "ubi9-hardened": "registry.access.redhat.com/ubi9/ubi:latest",
    "nginx": "docker.io/library/nginx:latest",
    "tomcat": "docker.io/library/tomcat:latest",
    "jre": "docker.io/library/eclipse-temurin:21-jre",
}
#: The package whose Wolfi version becomes the image's version tag.
VERSION_PACKAGE = {"nginx": "nginx-mainline", "jre": "openjdk-21-jre", "tomcat": "tomcat-11.0-openjdk-21"}
GROWTH_LIMIT = 0.10
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _load(path, default=None):
    if not os.path.isfile(path):
        if default is not None:
            return default
        raise SystemExit(f"missing {path}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _env_file(path):
    out = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


# --- version-tag ------------------------------------------------------------------

def version_tag(sbom_path, package):
    """apko's SPDX SBOM lists each installed package with its Wolfi version."""
    doc = _load(sbom_path)
    for p in doc.get("packages") or []:
        if p.get("name") == package:
            version = p.get("versionInfo") or ""
            return re.sub(r"-r\d+$", "", version)
    raise SystemExit(f"{package} is not in {sbom_path}")


# --- scan and registry readers -------------------------------------------------------

def trivy_counts(path):
    """Unique (id, package, version) per severity, and unique installed packages — the
    same counting the local kit uses, so the two tables agree."""
    doc = _load(path, default={})
    seen, packages = set(), set()
    counts = {s: 0 for s in SEVERITIES}
    for r in doc.get("Results") or []:
        for p in r.get("Packages") or []:
            packages.add((p.get("Name"), p.get("Version")))
        for v in r.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            if v.get("Severity") in counts:
                counts[v["Severity"]] += 1
    return {"critical": counts["CRITICAL"], "high": counts["HIGH"], "medium": counts["MEDIUM"],
            "low": counts["LOW"], "total": sum(counts.values()), "packages": len(packages)}


def layer_size(manifest):
    return sum(int(l.get("size", 0)) for l in manifest.get("layers") or [])


def _platforms(path):
    """[(arch, digest)] as finish-image.sh recorded them: every platform manifest of an
    index, or the single manifest of a one-platform image."""
    if not os.path.isfile(path):
        raise SystemExit(f"missing {path}")
    pairs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) == 2:
                pairs.append((parts[0], parts[1]))
    return pairs


# --- entry ---------------------------------------------------------------------------------

def _variant_entry(name, out_dir, variant, ref, refs, namespace, run_url, provenance_url, fallback):
    image = ref.split("@")[0]
    index_digest = ref.split("@")[1]
    platforms = {}
    for arch, digest in _platforms(os.path.join(out_dir, f"{variant}-platforms.txt")):
        manifest = _load(os.path.join(out_dir, f"{variant}-{arch}-manifest.json"))
        config = _load(os.path.join(out_dir, f"{variant}-{arch}-config.json"))
        scan = trivy_counts(os.path.join(out_dir, f"{variant}-{arch}.trivy.json"))
        platforms[arch] = {
            "digest": digest,
            "created": config.get("created"),
            "user": (config.get("config") or {}).get("User"),
            "size_bytes": layer_size(manifest),
            "package_count": scan["packages"],
            "vulnerabilities": {k: scan[k] for k in ("critical", "high", "medium", "low", "total")},
            "attestations": {
                "signature": f"{image}@{digest}",
                "spdx": f"{variant}-{arch}.spdx.json",
                "cyclonedx": f"{variant}-{arch}.cdx.json",
            },
            "scan": f"{variant}-{arch}.trivy.json",
        }
    # The Rekor entry cosign 2.x reported when the run verified its own signature.
    rekor = None
    verify_path = os.path.join(out_dir, f"{variant}-verify.json")
    if os.path.isfile(verify_path):
        for v in _load(verify_path, default=[]) or []:
            payload = ((v.get("optional") or {}).get("Bundle") or {}).get("Payload") or {}
            if payload.get("logIndex") is not None:
                rekor = int(payload["logIndex"])
                break
    tags = ["latest"] if variant == "prod" else ["latest-dev"]
    if variant == "prod":
        tags += [t for t in (refs.get("VERSION_TAG"), refs.get("DATE_TAG")) if t]
    created = next((p["created"] for p in platforms.values() if p.get("created")), None)
    entry = {
        "name": name, "family": FAMILY.get(name, "glibc"), "variant": variant,
        "image": image, "digest": index_digest, "tags": tags, "created": created,
        "platforms": platforms,
        "signature": {"keyless": True, "cert_identity": refs.get("CERT_IDENTITY"),
                      "oidc_issuer": "https://token.actions.githubusercontent.com",
                      "layout": "cosign classic .sig/.att tags", "verified_in_run": refs.get("VERIFIED") == "1",
                      "rekor_log_index": rekor},
        "provenance": ({"kind": "github-artifact-attestation", "slsa": "v1.0 Build Level 2",
                        "url": provenance_url} if provenance_url else None),
        "build_run_url": run_url,
        "source_date_epoch": refs.get("SOURCE_DATE_EPOCH"),
        "arch_fallback": "amd64 only (arm64 build failed under QEMU)" if (fallback and name == "ubi9-hardened") else None,
    }
    if variant == "prod":
        up_manifest = _load(os.path.join(out_dir, "upstream-amd64-manifest.json"), default={})
        entry["upstream"] = {
            "image": refs.get("UPSTREAM") or UPSTREAM.get(name), "digest": refs.get("UPSTREAM_DIGEST"),
            "platform": "linux/amd64",
            "size_bytes": layer_size(up_manifest) if up_manifest else None,
            "scan": trivy_counts(os.path.join(out_dir, "upstream-amd64.trivy.json")),
            "scan_file": "upstream-amd64.trivy.json",
        }
    return entry


def entry(args):
    refs = _env_file(os.path.join(args.out_dir, "refs.env"))
    entries = []
    for variant, key in (("prod", "PROD_REF"), ("dev", "DEV_REF")):
        if refs.get(key):
            entries.append(_variant_entry(args.name, args.out_dir, variant, refs[key], refs, args.namespace,
                                          args.run_url, args.provenance_url if variant == "prod" else args.dev_provenance_url,
                                          args.ubi_arch_fallback))
    path = os.path.join(args.out_dir, "entries.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    for e in entries:
        for arch, p in e["platforms"].items():
            v = p["vulnerabilities"]
            print(f"{e['name']} {e['variant']} {arch}: {p['package_count']} packages, {p['size_bytes']:,} bytes, "
                  f"C/H/M/L {v['critical']}/{v['high']}/{v['medium']}/{v['low']}")
    return 0


# --- growth ----------------------------------------------------------------------------------

def growth(args):
    baseline = _load(args.baseline, default={})
    entries = _load(args.entries)
    failures = []
    for e in entries:
        if e["variant"] != "prod":
            continue
        base = (baseline.get("images") or {}).get(e["name"])
        if not base:
            print(f"{e['name']}: no baseline yet; this run's numbers become the candidate baseline")
            continue
        for arch, p in e["platforms"].items():
            b = base.get(arch)
            if not b:
                print(f"{e['name']} {arch}: no baseline for this architecture")
                continue
            for metric in ("package_count", "size_bytes"):
                before, now = b.get(metric), p.get(metric)
                if not before or now is None:
                    continue
                change = (now - before) / before
                flag = "GROWTH" if change > GROWTH_LIMIT else "ok"
                print(f"{e['name']} {arch} {metric}: {before} -> {now} ({change:+.1%}) {flag}")
                if change > GROWTH_LIMIT:
                    failures.append(f"{e['name']} {arch} {metric} {before} -> {now} ({change:+.1%})")
    if failures:
        print("\nBuild failed the growth check (> 10% over baseline.json). If the growth is intended, "
              "update baseline.json in a reviewed change:\n  " + "\n  ".join(failures))
        return 1
    return 0


# --- merge ----------------------------------------------------------------------------------

def merge(args):
    entries = []
    for path in args.entries:
        entries.extend(_load(path))
    entries.sort(key=lambda e: (e["name"], e["variant"]))
    manifest = {
        "schema": "nineline.factory-manifest/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_url": args.run_url,
        "notes": args.rules_note,
        "tools": _load(args.tools, default={}) if args.tools else {},
        "images": entries,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    candidate = {"schema": "nineline.factory-baseline/1", "from_run": args.run_url, "images": {}}
    for e in entries:
        if e["variant"] == "prod":
            candidate["images"][e["name"]] = {arch: {"package_count": p["package_count"], "size_bytes": p["size_bytes"]}
                                              for arch, p in e["platforms"].items()}
    with open(args.baseline_out, "w", encoding="utf-8") as fh:
        json.dump(candidate, fh, indent=2)
    print(f"{len(entries)} entries -> {args.out}; baseline candidate -> {args.baseline_out}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("version-tag"); v.add_argument("--sbom", required=True); v.add_argument("--package", required=True)
    e = sub.add_parser("entry")
    e.add_argument("--name", required=True); e.add_argument("--out-dir", required=True)
    e.add_argument("--namespace", required=True); e.add_argument("--run-url", required=True)
    e.add_argument("--provenance-url", default=""); e.add_argument("--dev-provenance-url", default="")
    e.add_argument("--ubi-arch-fallback", action="store_true")
    g = sub.add_parser("growth"); g.add_argument("--baseline", required=True); g.add_argument("--entries", required=True)
    m = sub.add_parser("merge")
    m.add_argument("--out", required=True); m.add_argument("--baseline-out", required=True)
    m.add_argument("--run-url", required=True); m.add_argument("--rules-note", default="")
    m.add_argument("--tools", default="", help="tools.json written by the build job (tool name -> version)")
    m.add_argument("entries", nargs="+")
    a = ap.parse_args(argv)
    if a.cmd == "version-tag":
        print(version_tag(a.sbom, a.package))
        return 0
    return {"entry": entry, "growth": growth, "merge": merge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
