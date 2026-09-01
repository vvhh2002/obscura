#!/usr/bin/env python3
"""Verify that public ai_slide_matcher release assets contain no source code."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zipfile


REPOSITORY = "vvhh2002/ai_slide_matcher"
TOOLCHAIN = "1.98.0"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
TARGETS = {
    "x86_64-unknown-linux-musl": ("ai_slide_matcher", "tar.gz"),
    "aarch64-unknown-linux-musl": ("ai_slide_matcher", "tar.gz"),
    "x86_64-apple-darwin": ("ai_slide_matcher", "tar.gz"),
    "aarch64-apple-darwin": ("ai_slide_matcher", "tar.gz"),
    "x86_64-pc-windows-msvc": ("ai_slide_matcher.exe", "zip"),
}
COMMON_FILE_ORDER = (
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES",
    "examples/cases/README.md",
    "examples/cases/manifest.json",
    "examples/cases/SHA256SUMS",
    "examples/cases/compare/complete.png",
    "examples/cases/compare/gap.png",
    "examples/cases/match-alpha/background.png",
    "examples/cases/match-alpha/piece.png",
    "examples/cases/match-gray/background.png",
    "examples/cases/match-gray/piece.png",
)
# These are the reviewed, non-source runtime files at AI_SLIDE_MATCHER_REF.
# Updating the pinned matcher revision requires reviewing and updating any
# changed digest here before its public package can pass.
PUBLIC_FILE_SHA256 = {
    "README.md": "4bfac8d8ff3520d6b7116785c30eddb82fcf8c023ba232558eb1dfaf5b7ac64f",
    "LICENSE": "92fe74eb7fa586d7b59a2038a6658365278f13ce4b391dfa18dc1276f599d1f1",
    "THIRD_PARTY_NOTICES": "ad06e2ed208af7119512ad69cfacb13634c6c45f8c93bc9c12b761c5b655034a",
    "examples/cases/README.md": "96eba7e9c30ec63114180358ffc939f6b19854f81156b75af28bda704b899a9d",
    "examples/cases/manifest.json": "73616bf41a7df836d9babcedabd3fa82e0d592c77871eaaddc42d9c905c00284",
    "examples/cases/SHA256SUMS": "2f8297dfd2c134e443f79c70edc5107eb415b48a333dad9634301244064cfc77",
    "examples/cases/compare/complete.png": "ec8c1c98d14589638627346df8fe1bc118595b85c5bacb2d5f034babfa23e1b6",
    "examples/cases/compare/gap.png": "fe004183fc30f360da94d80c284ace576fd0653513df28ad45ecc6b8da8afbd9",
    "examples/cases/match-alpha/background.png": "60737bb14a188efc77cf207c614a76dcff943d9873e5f150b703ab8a9c2d46a2",
    "examples/cases/match-alpha/piece.png": "0713b30a4442efcb6d86bf0c2df40fafc1c5db77295d8a5e96493004d866944c",
    "examples/cases/match-gray/background.png": "1cf2f216a6bf6ebea74d40a8695f4646567d131925f506611c36233bacf80eae",
    "examples/cases/match-gray/piece.png": "3bc9087e3ade9189ceaf9f9695b73ca93b7d3a1bdb314c952a2c749fa5acf941",
}
COMMON_FILES = set(COMMON_FILE_ORDER)
GATES = {
    "locked_source_tests",
    "packaging_tests",
    "native_release_tests",
    "native_functional_smoke",
    "cross_platform_determinism",
    "platform_abi_checks",
    "binary_archive_verification",
}


class VerificationError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_tar_gz(
    prefix: str, files: list[tuple[str, bytes, bool]], epoch: int = 0
) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
            directory = tarfile.TarInfo(prefix + "/")
            directory.type = tarfile.DIRTYPE
            directory.mtime = epoch
            directory.uid = directory.gid = 0
            directory.uname = directory.gname = "root"
            directory.mode = 0o755
            bundle.addfile(directory)
            for name, data, executable in files:
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                info.mtime = epoch
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode = 0o755 if executable else 0o644
                bundle.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def canonical_zip(prefix: str, files: list[tuple[str, bytes, bool]]) -> bytes:
    raw = io.BytesIO()
    with zipfile.ZipFile(
        raw, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as bundle:
        for name, data, executable in files:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if executable else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3
            bundle.writestr(
                info,
                data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    return raw.getvalue()


def expected_archive_files(
    executable: str, contents: dict[str, bytes]
) -> list[tuple[str, bytes, bool]]:
    return [
        (executable, contents[executable], True),
        *((name, contents[name], False) for name in COMMON_FILE_ORDER),
    ]


def verify_public_file_contents(path: Path, contents: dict[str, bytes]) -> None:
    for name, expected_digest in PUBLIC_FILE_SHA256.items():
        if sha256_bytes(contents[name]) != expected_digest:
            raise VerificationError(
                f"{path.name}: reviewed public runtime material differs for {name}"
            )


def safe_relative(name: str, prefix: str) -> str:
    path = PurePosixPath(name)
    root = PurePosixPath(prefix)
    if path.is_absolute() or ".." in path.parts:
        raise VerificationError("archive contains an unsafe member path")
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise VerificationError("archive member escapes its declared root") from error
    if not relative.parts:
        raise VerificationError("archive contains a non-file root member")
    relative_name = str(relative)
    if name != f"{prefix}/{relative_name}":
        raise VerificationError("archive contains a non-canonical member path")
    return relative_name


def verify_tar(path: Path, prefix: str, executable: str) -> None:
    expected = {executable, *COMMON_FILES}
    with tarfile.open(path, "r:gz") as bundle:
        if bundle.pax_headers:
            raise VerificationError(f"{path.name}: global PAX metadata is forbidden")
        members = bundle.getmembers()
        directories = [member for member in members if member.isdir()]
        if len(directories) != 1 or directories[0].name.rstrip("/") != prefix:
            raise VerificationError(f"{path.name}: expected exactly one declared root directory")
        if any(not (member.isdir() or member.isfile()) for member in members):
            raise VerificationError(f"{path.name}: links and special members are forbidden")
        files = [member for member in members if member.isfile()]
        relative_files = [safe_relative(member.name, prefix) for member in files]
        actual = set(relative_files)
        if len(actual) != len(relative_files):
            raise VerificationError(f"{path.name}: duplicate archive members")
        if actual != expected:
            raise VerificationError(f"{path.name}: archive members differ from the allowlist")
        binary = files[relative_files.index(executable)]
        if binary.mode & 0o111 == 0:
            raise VerificationError(f"{path.name}: matcher binary is not executable")
        contents: dict[str, bytes] = {}
        for member, name in zip(files, relative_files, strict=True):
            allowed_pax = {} if not member.pax_headers else {"path": member.name}
            if member.pax_headers != allowed_pax:
                raise VerificationError(f"{path.name}: unexpected member PAX metadata")
            stream = bundle.extractfile(member)
            if stream is None:
                raise VerificationError(f"{path.name}: cannot read regular member")
            contents[name] = stream.read()
    verify_public_file_contents(path, contents)
    canonical = canonical_tar_gz(prefix, expected_archive_files(executable, contents))
    if path.read_bytes() != canonical:
        raise VerificationError(f"{path.name}: archive container is not canonical")


def verify_zip(path: Path, prefix: str, executable: str) -> None:
    expected = {executable, *COMMON_FILES}
    with zipfile.ZipFile(path) as bundle:
        if bundle.comment:
            raise VerificationError(f"{path.name}: ZIP archive comments are forbidden")
        infos = bundle.infolist()
        if any(info.is_dir() for info in infos):
            raise VerificationError(f"{path.name}: ZIP directory entries are forbidden")
        for info in infos:
            mode = info.external_attr >> 16
            if (
                info.create_system != 3
                or not stat.S_ISREG(mode)
                or info.comment
                or info.extra
            ):
                raise VerificationError(f"{path.name}: ZIP links and special members are forbidden")
        relative_files = [safe_relative(info.filename, prefix) for info in infos]
        actual = set(relative_files)
        if len(actual) != len(relative_files):
            raise VerificationError(f"{path.name}: duplicate archive members")
        if actual != expected:
            raise VerificationError(f"{path.name}: archive members differ from the allowlist")
        binary = infos[relative_files.index(executable)]
        mode = (binary.external_attr >> 16) & 0o777
        if mode & 0o111 == 0:
            raise VerificationError(f"{path.name}: matcher binary is not executable")
        contents = {
            name: bundle.read(info)
            for info, name in zip(infos, relative_files, strict=True)
        }
    verify_public_file_contents(path, contents)
    canonical = canonical_zip(prefix, expected_archive_files(executable, contents))
    if path.read_bytes() != canonical:
        raise VerificationError(f"{path.name}: archive container is not canonical")


def parse_provenance(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise VerificationError("matcher provenance is malformed")
        values[key] = value
    return values


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("matcher test report contains duplicate keys")
        result[key] = value
    return result


def verify_checksums(root: Path, expected_files: set[str]) -> None:
    checksum_path = root / "SHA256SUMS"
    observed: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        name = name.removeprefix("./")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", digest) or name in observed:
            raise VerificationError("matcher SHA256SUMS is malformed")
        observed[name] = digest
    wanted = expected_files - {"SHA256SUMS"}
    if set(observed) != wanted:
        raise VerificationError("matcher SHA256SUMS file set differs from the public allowlist")
    for name, digest in observed.items():
        if sha256(root / name) != digest:
            raise VerificationError(f"matcher checksum differs for {name}")


def verify_staging(root: Path, executable: str) -> None:
    if executable not in {"ai_slide_matcher", "ai_slide_matcher.exe"}:
        raise VerificationError("matcher staging executable name is not allowed")
    if not root.is_dir() or root.is_symlink():
        raise VerificationError("matcher staging root must be a regular directory")
    expected_files = {executable, "LICENSE", "THIRD_PARTY_NOTICES"}
    entries = list(root.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise VerificationError("matcher staging may contain only regular allowlisted files")
    if {entry.name for entry in entries} != expected_files:
        raise VerificationError("matcher staging file set differs from the allowlist")
    if sha256(root / "LICENSE") != PUBLIC_FILE_SHA256["LICENSE"]:
        raise VerificationError("matcher staging LICENSE differs from the reviewed file")
    if (
        sha256(root / "THIRD_PARTY_NOTICES")
        != PUBLIC_FILE_SHA256["THIRD_PARTY_NOTICES"]
    ):
        raise VerificationError("matcher staging notices differ from the reviewed file")


def verify_release(root: Path, version: str, commit: str) -> None:
    if not VERSION_RE.fullmatch(version):
        raise VerificationError(f"invalid matcher version: {version!r}")
    if not COMMIT_RE.fullmatch(commit):
        raise VerificationError(f"invalid matcher commit: {commit!r}")
    if not root.is_dir() or root.is_symlink():
        raise VerificationError("matcher release root must be a regular directory")

    archives = {
        f"ai_slide_matcher-v{version}-{target}.{extension}"
        for target, (_executable, extension) in TARGETS.items()
    }
    expected_files = {
        *archives,
        "SHA256SUMS",
        "ai_slide_matcher-PROVENANCE.txt",
        "ai_slide_matcher-TEST-REPORT.json",
    }
    entries = list(root.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise VerificationError("matcher release root may contain only regular allowlisted files")
    actual_files = {entry.name for entry in entries}
    if actual_files != expected_files:
        raise VerificationError("matcher release file set differs from the allowlist")

    for target, (executable, extension) in TARGETS.items():
        prefix = f"ai_slide_matcher-v{version}-{target}"
        archive = root / f"{prefix}.{extension}"
        if extension == "zip":
            verify_zip(archive, prefix, executable)
        else:
            verify_tar(archive, prefix, executable)

    provenance = parse_provenance(root / "ai_slide_matcher-PROVENANCE.txt")
    expected_provenance = {
        "repository": f"https://github.com/{REPOSITORY}",
        "commit": commit,
        "rust_toolchain": TOOLCHAIN,
        "version": version,
    }
    if provenance != expected_provenance:
        raise VerificationError("matcher provenance differs from the pinned build")

    report = json.loads(
        (root / "ai_slide_matcher-TEST-REPORT.json").read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_json_keys,
    )
    if not isinstance(report, dict):
        raise VerificationError("matcher test report must be an object")
    expected_report_keys = {
        "schema_version",
        "repository",
        "commit",
        "version",
        "source_code_included",
        "gates",
        "native_targets",
    }
    if set(report) != expected_report_keys:
        raise VerificationError("matcher test report fields differ from the public schema")
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise VerificationError("matcher test report schema is unsupported")
    if report.get("repository") != REPOSITORY or report.get("commit") != commit:
        raise VerificationError("matcher test report provenance differs")
    if report.get("version") != version or report.get("source_code_included") is not False:
        raise VerificationError("matcher test report does not enforce binary-only publication")
    gates = report.get("gates")
    if not isinstance(gates, dict) or set(gates) != GATES or set(gates.values()) != {"passed"}:
        raise VerificationError("matcher test report release gates are incomplete")
    native_targets = report.get("native_targets")
    if (
        not isinstance(native_targets, list)
        or len(native_targets) != len(TARGETS)
        or set(native_targets) != set(TARGETS)
    ):
        raise VerificationError("matcher test report native targets are incomplete")

    verify_checksums(root, expected_files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--archives", type=Path)
    scope.add_argument("--staging", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--commit")
    parser.add_argument("--executable")
    args = parser.parse_args(argv)
    try:
        if args.staging is not None:
            if args.executable is None or args.version is not None or args.commit is not None:
                raise VerificationError("matcher staging verification arguments are invalid")
            verify_staging(args.staging, args.executable)
            print("MATCHER_STAGING_VERIFY_PASS")
            return 0
        if args.version is None or args.commit is None or args.executable is not None:
            raise VerificationError("matcher release verification arguments are invalid")
        verify_release(args.archives, args.version, args.commit)
    except VerificationError as error:
        raise SystemExit(f"matcher binary release verification failed: {error}") from error
    except (OSError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SystemExit("matcher binary release verification failed: malformed input") from error
    print("MATCHER_BINARY_RELEASE_VERIFY_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
