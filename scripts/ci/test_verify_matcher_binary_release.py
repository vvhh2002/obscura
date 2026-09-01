from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_matcher_binary_release import (
    COMMON_FILE_ORDER,
    COMMON_FILES,
    GATES,
    PUBLIC_FILE_SHA256,
    REPOSITORY,
    TARGETS,
    TOOLCHAIN,
    VerificationError,
    canonical_tar_gz,
    canonical_zip,
    main as verify_main,
    verify_release,
    verify_staging,
)


VERSION = "0.1.0+build.1788194189"
COMMIT = "132a833b72a6593d04f7400315ec82100d261d8c"


class MatcherBinaryReleaseVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="matcher-public-release-")
        self.root = Path(self.temporary.name)
        fixture_hashes = {
            name: hashlib.sha256(f"public fixture {name}\n".encode()).hexdigest()
            for name in COMMON_FILES
        }
        self.public_hash_patch = mock.patch.dict(
            PUBLIC_FILE_SHA256, fixture_hashes, clear=False
        )
        self.public_hash_patch.start()
        self.write_release()

    def tearDown(self) -> None:
        self.public_hash_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def archive_files(executable: str) -> dict[str, bytes]:
        return {
            executable: b"native binary",
            **{name: f"public fixture {name}\n".encode() for name in COMMON_FILES},
        }

    def write_tar(
        self,
        target: str,
        executable: str,
        extra: str | None = None,
        duplicate: str | None = None,
        replacement: tuple[str, bytes] | None = None,
    ) -> None:
        prefix = f"ai_slide_matcher-v{VERSION}-{target}"
        destination = self.root / f"{prefix}.tar.gz"
        files = self.archive_files(executable)
        if replacement is not None:
            files[replacement[0]] = replacement[1]
        if extra is None and duplicate is None:
            ordered = [(executable, files[executable], True)] + [
                (name, files[name], False) for name in COMMON_FILE_ORDER
            ]
            destination.write_bytes(canonical_tar_gz(prefix, ordered))
            return
        with tarfile.open(destination, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
            directory = tarfile.TarInfo(prefix + "/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.uname = directory.gname = "root"
            bundle.addfile(directory)
            if extra is not None:
                files[extra] = b"private source"
            for name, data in files.items():
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                info.mode = 0o755 if name == executable else 0o644
                info.uname = info.gname = "root"
                bundle.addfile(info, io.BytesIO(data))
            if duplicate is not None:
                data = b"duplicate member"
                info = tarfile.TarInfo(f"{prefix}/{duplicate}")
                info.size = len(data)
                info.mode = 0o755 if duplicate == executable else 0o644
                info.uname = info.gname = "root"
                bundle.addfile(info, io.BytesIO(data))

    def write_zip(
        self,
        target: str,
        executable: str,
        duplicate: str | None = None,
        symlink: str | None = None,
    ) -> None:
        prefix = f"ai_slide_matcher-v{VERSION}-{target}"
        destination = self.root / f"{prefix}.zip"
        files = self.archive_files(executable)
        if duplicate is None and symlink is None:
            ordered = [(executable, files[executable], True)] + [
                (name, files[name], False) for name in COMMON_FILE_ORDER
            ]
            destination.write_bytes(canonical_zip(prefix, ordered))
            return
        with zipfile.ZipFile(destination, "w") as bundle:
            for name, data in files.items():
                info = zipfile.ZipInfo(f"{prefix}/{name}")
                if name == symlink:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    data = b"private-source"
                else:
                    mode = 0o755 if name == executable else 0o644
                    info.external_attr = (stat.S_IFREG | mode) << 16
                info.create_system = 3
                bundle.writestr(info, data)
            if duplicate is not None:
                info = zipfile.ZipInfo(f"{prefix}/{duplicate}")
                mode = 0o755 if duplicate == executable else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.create_system = 3
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(info, b"duplicate member")

    def write_checksums(self) -> None:
        lines = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            if path.name == "SHA256SUMS":
                continue
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
        (self.root / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    def write_release(self) -> None:
        for target, (executable, extension) in TARGETS.items():
            if extension == "zip":
                self.write_zip(target, executable)
            else:
                self.write_tar(target, executable)
        (self.root / "ai_slide_matcher-PROVENANCE.txt").write_text(
            "\n".join(
                [
                    f"repository=https://github.com/{REPOSITORY}",
                    f"commit={COMMIT}",
                    f"rust_toolchain={TOOLCHAIN}",
                    f"version={VERSION}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (self.root / "ai_slide_matcher-TEST-REPORT.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": REPOSITORY,
                    "commit": COMMIT,
                    "version": VERSION,
                    "source_code_included": False,
                    "gates": {name: "passed" for name in GATES},
                    "native_targets": list(TARGETS),
                }
            ),
            encoding="utf-8",
        )
        self.write_checksums()

    def test_accepts_exact_binary_only_release(self) -> None:
        verify_release(self.root, VERSION, COMMIT)

    def test_staging_accepts_only_binary_and_reviewed_legal_files(self) -> None:
        staging = self.root / "staging"
        staging.mkdir()
        (staging / "ai_slide_matcher").write_bytes(b"native binary")
        for name in ("LICENSE", "THIRD_PARTY_NOTICES"):
            (staging / name).write_bytes(f"public fixture {name}\n".encode())
        verify_staging(staging, "ai_slide_matcher")

        (staging / "src.rs").write_text("private source", encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "file set differs"):
            verify_staging(staging, "ai_slide_matcher")

    def test_staging_cli_boundary_rejects_a_symlink_root(self) -> None:
        staging = self.root / "staging-target"
        staging.mkdir()
        (staging / "ai_slide_matcher").write_bytes(b"native binary")
        for name in ("LICENSE", "THIRD_PARTY_NOTICES"):
            (staging / name).write_bytes(f"public fixture {name}\n".encode())
        link = self.root / "staging-link"
        link.symlink_to(staging, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "regular directory"):
            verify_main(
                [
                    "--staging",
                    str(link),
                    "--executable",
                    "ai_slide_matcher",
                ]
            )

    def test_staging_rejects_crlf_conversion_of_reviewed_legal_files(self) -> None:
        staging = self.root / "staging-crlf"
        staging.mkdir()
        (staging / "ai_slide_matcher.exe").write_bytes(b"native binary")
        (staging / "LICENSE").write_bytes(b"public fixture LICENSE\r\n")
        (staging / "THIRD_PARTY_NOTICES").write_bytes(
            b"public fixture THIRD_PARTY_NOTICES\n"
        )
        with self.assertRaisesRegex(VerificationError, "LICENSE differs"):
            verify_staging(staging, "ai_slide_matcher.exe")

    def test_rejects_source_member_even_with_updated_checksum(self) -> None:
        target = "x86_64-unknown-linux-musl"
        self.write_tar(target, "ai_slide_matcher", "src/lib.rs")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "members differ from the allowlist"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_changed_allowlisted_content(self) -> None:
        target = "x86_64-unknown-linux-musl"
        self.write_tar(
            target,
            "ai_slide_matcher",
            replacement=("README.md", b"private source in an allowlisted file"),
        )
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "reviewed public runtime material"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_duplicate_tar_member_hidden_by_set_comparison(self) -> None:
        target = "x86_64-unknown-linux-musl"
        self.write_tar(target, "ai_slide_matcher", duplicate="README.md")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "duplicate archive members"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_duplicate_zip_member_hidden_by_set_comparison(self) -> None:
        target = "x86_64-pc-windows-msvc"
        self.write_zip(target, "ai_slide_matcher.exe", duplicate="README.md")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "duplicate archive members"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_zip_symlink_with_an_allowlisted_name(self) -> None:
        target = "x86_64-pc-windows-msvc"
        self.write_zip(target, "ai_slide_matcher.exe", symlink="README.md")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "links and special members"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_extra_directory_ignored_by_regular_file_globs(self) -> None:
        extra = self.root / "src"
        extra.mkdir()
        (extra / "lib.rs").write_text("private source", encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "only regular allowlisted files"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_report_that_claims_source_is_included(self) -> None:
        report_path = self.root / "ai_slide_matcher-TEST-REPORT.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["source_code_included"] = True
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "binary-only publication"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_extra_report_field_even_with_updated_checksum(self) -> None:
        report_path = self.root / "ai_slide_matcher-TEST-REPORT.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["private_source"] = "fn implementation() {}"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "fields differ"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_zip_archive_comment(self) -> None:
        target = "x86_64-pc-windows-msvc"
        prefix = f"ai_slide_matcher-v{VERSION}-{target}"
        path = self.root / f"{prefix}.zip"
        with zipfile.ZipFile(path, "a") as bundle:
            bundle.comment = b"private source"
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "archive comments"):
            verify_release(self.root, VERSION, COMMIT)

    def test_rejects_tar_global_pax_payload(self) -> None:
        target = "x86_64-unknown-linux-musl"
        prefix = f"ai_slide_matcher-v{VERSION}-{target}"
        path = self.root / f"{prefix}.tar.gz"
        files = self.archive_files("ai_slide_matcher")
        with tarfile.open(
            path,
            "w:gz",
            format=tarfile.PAX_FORMAT,
            pax_headers={"source": "fn private() {}"},
        ) as bundle:
            directory = tarfile.TarInfo(prefix + "/")
            directory.type = tarfile.DIRTYPE
            bundle.addfile(directory)
            for name, data in files.items():
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(data)
                info.mode = 0o755 if name == "ai_slide_matcher" else 0o644
                bundle.addfile(info, io.BytesIO(data))
        self.write_checksums()
        with self.assertRaisesRegex(VerificationError, "global PAX metadata"):
            verify_release(self.root, VERSION, COMMIT)


if __name__ == "__main__":
    unittest.main()
