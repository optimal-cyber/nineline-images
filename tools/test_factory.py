"""factory.py: the numbers in manifest.json come straight from scanner and registry output."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import factory  # noqa: E402


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


def trivy(vulns, packages):
    return {"Results": [{"Packages": [{"Name": n, "Version": v} for n, v in packages],
                         "Vulnerabilities": [{"VulnerabilityID": i, "PkgName": p, "InstalledVersion": v, "Severity": s}
                                             for i, p, v, s in vulns]}]}


def test_version_tag_strips_the_release_suffix(tmp_path):
    sbom = write(str(tmp_path / "sbom.json"), {"packages": [
        {"name": "glibc", "versionInfo": "2.42-r5"}, {"name": "nginx-mainline", "versionInfo": "1.31.6-r3"}]})
    assert factory.version_tag(sbom, "nginx-mainline") == "1.31.6"
    with pytest.raises(SystemExit):
        factory.version_tag(sbom, "tomcat-11.0-openjdk-21")


def test_trivy_counts_dedupe_like_the_local_kit(tmp_path):
    path = write(str(tmp_path / "t.json"), trivy(
        [("CVE-1", "openssl", "3.0", "HIGH"), ("CVE-1", "openssl", "3.0", "HIGH"),   # duplicate result rows
         ("CVE-2", "zlib", "1.2", "MEDIUM"), ("CVE-3", "zlib", "1.2", "UNKNOWN")],
        [("openssl", "3.0"), ("zlib", "1.2"), ("zlib", "1.2")]))
    c = factory.trivy_counts(path)
    assert c == {"critical": 0, "high": 1, "medium": 1, "low": 0, "total": 2, "packages": 2}


def _out_dir(tmp_path, name="nginx", with_dev=True, fallback_single=False):
    out = tmp_path / "out" / name
    os.makedirs(out)
    refs = [f"PROD_REF=ghcr.io/o/nineline/{name}@sha256:idx",
            "VERSION_TAG=1.31.6" if name == "nginx" else "VERSION_TAG=", "DATE_TAG=2026.10.15",
            "SOURCE_DATE_EPOCH=1760500000", "UPSTREAM=docker.io/library/nginx:latest",
            "UPSTREAM_DIGEST=sha256:up", "CERT_IDENTITY=https://github.com/o/nineline-images/.github/workflows/factory.yml@refs/heads/main",
            "VERIFIED=1"]
    if with_dev:
        refs.insert(1, f"DEV_REF=ghcr.io/o/nineline/{name}@sha256:dev")
    (out / "refs.env").write_text("\n".join(refs) + "\n")
    for variant in ["prod"] + (["dev"] if with_dev else []):
        arches = ["amd64"] if fallback_single else ["amd64", "arm64"]
        (out / f"{variant}-platforms.txt").write_text("".join(f"{a} sha256:{variant}{a}\n" for a in arches))
        for a in arches:
            write(str(out / f"{variant}-{a}-manifest.json"), {"layers": [{"size": 1000}, {"size": 2345}]})
            write(str(out / f"{variant}-{a}-config.json"), {"created": "2026-10-15T06:31:00Z", "config": {"User": "65532"}})
            write(str(out / f"{variant}-{a}.trivy.json"), trivy([("CVE-9", "nginx", "1.31.6", "LOW")], [("nginx", "1.31.6"), ("glibc", "2.42")]))
    write(str(out / "upstream-amd64-manifest.json"), {"layers": [{"size": 70_000_000}]})
    write(str(out / "upstream-amd64.trivy.json"), trivy([("CVE-5", "libc6", "2.36", "CRITICAL"), ("CVE-6", "zlib", "1.2", "HIGH")],
                                                        [(f"p{i}", "1") for i in range(140)]))
    return out


def test_entry_builds_prod_and_dev_from_the_files(tmp_path):
    out = _out_dir(tmp_path)
    assert factory.main(["entry", "--name", "nginx", "--out-dir", str(out), "--namespace", "ghcr.io/o/nineline",
                         "--run-url", "https://github.com/o/nineline-images/actions/runs/1",
                         "--provenance-url", "https://github.com/o/nineline-images/attestations/7"]) == 0
    entries = json.load(open(out / "entries.json"))
    assert [e["variant"] for e in entries] == ["prod", "dev"]
    prod = entries[0]
    assert prod["family"] == "glibc" and prod["digest"] == "sha256:idx"
    assert prod["tags"] == ["latest", "1.31.6", "2026.10.15"] and entries[1]["tags"] == ["latest-dev"]
    assert set(prod["platforms"]) == {"amd64", "arm64"}
    assert prod["platforms"]["amd64"]["size_bytes"] == 3345 and prod["platforms"]["amd64"]["package_count"] == 2
    assert prod["platforms"]["amd64"]["vulnerabilities"]["low"] == 1
    assert prod["created"] == "2026-10-15T06:31:00Z"
    assert prod["signature"]["verified_in_run"] is True and prod["provenance"]["slsa"] == "v1.0 Build Level 2"
    assert prod["upstream"]["scan"]["critical"] == 1 and prod["upstream"]["scan"]["packages"] == 140
    assert prod["upstream"]["size_bytes"] == 70_000_000 and prod["upstream"]["digest"] == "sha256:up"
    assert "upstream" not in entries[1]


def test_single_platform_fallback_is_recorded(tmp_path):
    out = _out_dir(tmp_path, name="ubi9-hardened", with_dev=False, fallback_single=True)
    factory.main(["entry", "--name", "ubi9-hardened", "--out-dir", str(out), "--namespace", "ghcr.io/o/nineline",
                  "--run-url", "u", "--ubi-arch-fallback"])
    (prod,) = json.load(open(out / "entries.json"))
    assert list(prod["platforms"]) == ["amd64"] and prod["family"] == "redhat"
    assert "arm64 build failed" in prod["arch_fallback"] and prod["tags"] == ["latest", "2026.10.15"]


def test_growth_check_fails_over_ten_percent(tmp_path, capsys):
    out = _out_dir(tmp_path)
    factory.main(["entry", "--name", "nginx", "--out-dir", str(out), "--namespace", "n", "--run-url", "u"])
    entries = str(out / "entries.json")
    no_baseline = str(tmp_path / "missing.json")
    assert factory.main(["growth", "--baseline", no_baseline, "--entries", entries]) == 0
    ok = write(str(tmp_path / "b1.json"), {"images": {"nginx": {"amd64": {"package_count": 2, "size_bytes": 3100}}}})
    assert factory.main(["growth", "--baseline", ok, "--entries", entries]) == 0
    grown = write(str(tmp_path / "b2.json"), {"images": {"nginx": {"amd64": {"package_count": 2, "size_bytes": 3000}}}})
    assert factory.main(["growth", "--baseline", grown, "--entries", entries]) == 1
    assert "size_bytes 3000 -> 3345 (+11.5%)" in capsys.readouterr().out


def test_merge_writes_manifest_and_baseline_candidate(tmp_path):
    a = _out_dir(tmp_path, "nginx")
    factory.main(["entry", "--name", "nginx", "--out-dir", str(a), "--namespace", "n", "--run-url", "u"])
    b = _out_dir(tmp_path, "ubi9-hardened", with_dev=False, fallback_single=True)
    factory.main(["entry", "--name", "ubi9-hardened", "--out-dir", str(b), "--namespace", "n", "--run-url", "u"])
    m, bl = str(tmp_path / "manifest.json"), str(tmp_path / "baseline.json")
    assert factory.main(["merge", "--out", m, "--baseline-out", bl, "--run-url", "u", "--rules-note", "n",
                         str(a / "entries.json"), str(b / "entries.json")]) == 0
    manifest = json.load(open(m))
    assert [(e["name"], e["variant"]) for e in manifest["images"]] == [("nginx", "dev"), ("nginx", "prod"), ("ubi9-hardened", "prod")]
    baseline = json.load(open(bl))
    assert baseline["images"]["nginx"]["arm64"]["size_bytes"] == 3345 and "dev" not in json.dumps(baseline)
