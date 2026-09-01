from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sanitize_matcher_smoke import (
    SmokeManifestError,
    canonical_manifest,
    main,
    render_canonical_manifest,
    sanitize_manifest,
)


TARGET = "macos-arm64"
VERSION = "0.1.0+build.1788194189"


class MatcherSmokeSanitizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="matcher-smoke-sanitize-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "private-input.json"
        self.output = self.root / "public-output.json"
        self.manifest = canonical_manifest(TARGET, VERSION)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, manifest: object) -> None:
        self.source.write_text(json.dumps(manifest), encoding="utf-8")

    def assert_rejected(self, manifest: object) -> SmokeManifestError:
        self.write(manifest)
        with self.assertRaises(SmokeManifestError) as raised:
            sanitize_manifest(self.source, self.output, TARGET, VERSION)
        self.assertFalse(self.output.exists())
        return raised.exception

    def test_accepts_exact_manifest_and_rebuilds_canonical_json(self) -> None:
        # Deliberately use non-canonical whitespace and key ordering as input.
        source = {
            "cases": self.manifest["cases"],
            "target": self.manifest["target"],
            "schema": self.manifest["schema"],
        }
        self.source.write_text(json.dumps(source, separators=(", ", ":")), encoding="utf-8")

        sanitize_manifest(self.source, self.output, TARGET, VERSION)

        self.assertEqual(
            self.output.read_text(encoding="utf-8"),
            render_canonical_manifest(TARGET, VERSION),
        )

    def test_rejects_extra_top_level_key(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["private_source"] = "src/lib.rs"
        self.assert_rejected(manifest)

    def test_rejects_extra_case_key(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["cases"][1]["stderr"] = "private diagnostic"
        self.assert_rejected(manifest)

    def test_rejects_duplicate_root_and_nested_keys(self) -> None:
        encoded = json.dumps(self.manifest)
        duplicate_root = '{"schema": 1, ' + encoded[1:]
        duplicate_case = encoded.replace(
            '"name": "version"',
            '"name": "version", "name": "version"',
            1,
        )
        for payload in (duplicate_root, duplicate_case):
            with self.subTest(payload=payload[:32]):
                self.source.write_text(payload, encoding="utf-8")
                with self.assertRaisesRegex(SmokeManifestError, "duplicate object key"):
                    sanitize_manifest(self.source, self.output, TARGET, VERSION)
                self.assertFalse(self.output.exists())

    def test_refuses_an_existing_or_linked_output(self) -> None:
        self.write(self.manifest)
        victim = self.root / "verified-binary"
        victim.write_bytes(b"native binary")
        self.output.symlink_to(victim)

        with self.assertRaises(FileExistsError):
            sanitize_manifest(self.source, self.output, TARGET, VERSION)

        self.assertEqual(victim.read_bytes(), b"native binary")

    def test_rejects_stdout_source_injection_without_echoing_payload(self) -> None:
        marker = "SECRET_SOURCE: include_str!(\"src/lib.rs\")"
        manifest = copy.deepcopy(self.manifest)
        manifest["cases"][1]["stdout"] = marker
        self.write(manifest)
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            result = main(
                [
                    "--input",
                    str(self.source),
                    "--output",
                    str(self.output),
                    "--target",
                    TARGET,
                    "--version",
                    VERSION,
                ]
            )

        self.assertEqual(result, 1)
        self.assertNotIn(marker, stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_target(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["target"] = "linux-x64-musl"
        self.assert_rejected(manifest)

        self.write(self.manifest)
        with self.assertRaises(SmokeManifestError):
            sanitize_manifest(self.source, self.output, "freebsd-x64", VERSION)

    def test_rejects_wrong_or_invalid_version(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["cases"][0]["stdout"] = "ai_slide_matcher 0.1.1+build.1788194189\n"
        self.assert_rejected(manifest)

        self.write(self.manifest)
        with self.assertRaises(SmokeManifestError):
            sanitize_manifest(self.source, self.output, TARGET, "01.0.0-private")


if __name__ == "__main__":
    unittest.main()
