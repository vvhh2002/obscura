from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parent))

from next_release_tag import (
    ReleaseTagError,
    read_git_tags,
    read_occupied_tags,
    select_release_tag,
)


class AutomaticReleaseTagTests(unittest.TestCase):
    def test_starts_at_initial_version_without_stable_tags(self) -> None:
        self.assertEqual(
            select_release_tag([], [], initial_version="0.1.0"),
            "v0.1.0",
        )

    def test_increments_highest_stable_patch_numerically(self) -> None:
        self.assertEqual(
            select_release_tag(
                ["v0.9.9", "v0.10.0", "v0.2.100", "not-a-version"],
                [],
            ),
            "v0.10.1",
        )

    def test_ignores_prerelease_build_metadata_and_noncanonical_tags(self) -> None:
        self.assertEqual(
            select_release_tag(
                [
                    "v0.1.3",
                    "v9.0.0-rc.1",
                    "v9.0.0+build.1",
                    "v01.2.3",
                    "0.1.4",
                ],
                [],
            ),
            "v0.1.4",
        )

    def test_reuses_highest_stable_tag_on_selected_commit(self) -> None:
        self.assertEqual(
            select_release_tag(
                ["v0.1.3", "v0.1.4"],
                ["v0.1.3", "v0.1.4", "v0.2.0-rc.1"],
            ),
            "v0.1.4",
        )

    def test_reuses_older_tag_when_explicitly_rebuilding_older_commit(self) -> None:
        self.assertEqual(
            select_release_tag(["v0.1.3", "v0.1.4"], ["v0.1.3"]),
            "v0.1.3",
        )

    def test_rejects_noncanonical_initial_version(self) -> None:
        with self.assertRaisesRegex(ReleaseTagError, "canonical stable SemVer"):
            select_release_tag([], [], initial_version="01.0.0")

    def test_release_with_deleted_tag_keeps_version_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            occupied = Path(directory) / "release-tags.txt"
            occupied.write_text("v0.1.3\nv0.1.4\n", encoding="utf-8")

            self.assertEqual(
                select_release_tag(
                    ["v0.1.3", *read_occupied_tags(occupied)],
                    [],
                ),
                "v0.1.5",
            )

    def test_reads_lightweight_and_annotated_tags_at_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            commands = [
                ["git", "init", "--quiet", str(repository)],
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.name",
                    "Release Tests",
                ],
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "release-tests@example.invalid",
                ],
                [
                    "git",
                    "-C",
                    str(repository),
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "initial",
                ],
                ["git", "-C", str(repository), "tag", "v0.1.0"],
                [
                    "git",
                    "-C",
                    str(repository),
                    "tag",
                    "--annotate",
                    "v0.1.1",
                    "-m",
                    "release",
                ],
            ]
            for command in commands:
                subprocess.run(command, check=True)

            self.assertEqual(
                set(read_git_tags(repository, "--points-at", "HEAD")),
                {"v0.1.0", "v0.1.1"},
            )


if __name__ == "__main__":
    unittest.main()
