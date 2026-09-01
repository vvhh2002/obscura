#!/usr/bin/env python3
"""Validate the provenance and license record for every vendored Rust crate."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = ROOT / "vendor"
ROOT_MANIFEST = ROOT / "Cargo.toml"
FIELD_RE = re.compile(r'^\s*(name|version|license)\s*=\s*"([^"]+)"\s*$')
SHA256_RE = re.compile(r"^- Source archive SHA-256: `([0-9a-f]{64})`$", re.MULTILINE)
PACKAGE_RE = re.compile(r"^- Package: `([^`]+)`$", re.MULTILINE)
LICENSE_RE = re.compile(r"^- License: ([^;\n]+); see .+$", re.MULTILINE)
UPSTREAM_RE = re.compile(r"^- Upstream repository: <https://[^>]+>$", re.MULTILINE)


def manifest_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    in_package = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if not in_package:
            continue
        match = FIELD_RE.match(line)
        if match and match.group(1) not in fields:
            fields[match.group(1)] = match.group(2)
    return fields


def fail(message: str) -> None:
    print(f"vendor check: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if not VENDOR_ROOT.is_dir():
        return

    root_manifest = ROOT_MANIFEST.read_text(encoding="utf-8")
    crates = sorted(path for path in VENDOR_ROOT.iterdir() if path.is_dir())
    if not crates:
        fail("vendor directory exists but contains no crate")

    for crate in crates:
        if crate.is_symlink():
            fail(f"{crate.relative_to(ROOT)} must not be a symlink")
        for descendant in crate.rglob("*"):
            if descendant.is_symlink():
                fail(f"vendored source contains a symlink: {descendant.relative_to(ROOT)}")

        required = [crate / "Cargo.toml", crate / "OBSCURA-VENDORING.md"]
        missing = [path.name for path in required if not path.is_file()]
        if missing:
            fail(f"{crate.relative_to(ROOT)} is missing {', '.join(missing)}")
        license_files = sorted(path for path in crate.glob("LICENSE*") if path.is_file())
        if not license_files:
            fail(f"{crate.relative_to(ROOT)} has no LICENSE file")
        if any(path.stat().st_size == 0 for path in license_files):
            fail(f"{crate.relative_to(ROOT)} has an empty LICENSE file")

        fields = manifest_fields(crate / "Cargo.toml")
        for field in ("name", "version", "license"):
            if not fields.get(field):
                fail(f"{crate.relative_to(ROOT)}/Cargo.toml has no package.{field}")

        record = (crate / "OBSCURA-VENDORING.md").read_text(encoding="utf-8")
        package = PACKAGE_RE.search(record)
        license_record = LICENSE_RE.search(record)
        if not package or package.group(1) != f"{fields['name']} {fields['version']}":
            fail(f"{crate.relative_to(ROOT)} has a stale package provenance record")
        if not SHA256_RE.search(record):
            fail(f"{crate.relative_to(ROOT)} has no source archive SHA-256")
        if not UPSTREAM_RE.search(record):
            fail(f"{crate.relative_to(ROOT)} has no HTTPS upstream repository")
        if not license_record or license_record.group(1).strip() != fields["license"]:
            fail(f"{crate.relative_to(ROOT)} has a stale license provenance record")

        relative = crate.relative_to(ROOT).as_posix()
        patch_re = re.compile(
            rf"^\s*{re.escape(fields['name'])}\s*=\s*\{{[^\n]*\bpath\s*=\s*\"{re.escape(relative)}\"[^\n]*\}}\s*$",
            re.MULTILINE,
        )
        if not patch_re.search(root_manifest):
            fail(f"Cargo.toml does not patch {fields['name']} to {relative}")

        print(
            f"vendor check: {fields['name']} {fields['version']} "
            f"({fields['license']}) at {relative}"
        )


if __name__ == "__main__":
    main()
