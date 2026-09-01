#!/usr/bin/env python3
"""Select the stable release tag for a manual Release workflow run."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
from typing import Iterable


STABLE_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)


class ReleaseTagError(ValueError):
    """Raised when an automatic release tag cannot be selected safely."""


def parse_stable_tag(tag: str) -> tuple[int, int, int] | None:
    match = STABLE_TAG.fullmatch(tag)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def normalize_initial_version(version: str) -> str:
    tag = version if version.startswith("v") else f"v{version}"
    if parse_stable_tag(tag) is None:
        raise ReleaseTagError("initial version must be a canonical stable SemVer")
    return tag


def select_release_tag(
    all_tags: Iterable[str],
    head_tags: Iterable[str],
    initial_version: str = "0.1.0",
) -> str:
    """Reuse a stable tag on HEAD, otherwise increment the highest patch."""

    stable_head = [
        (parsed, tag)
        for tag in head_tags
        if (parsed := parse_stable_tag(tag)) is not None
    ]
    if stable_head:
        return max(stable_head)[1]

    stable_versions = [
        parsed
        for tag in all_tags
        if (parsed := parse_stable_tag(tag)) is not None
    ]
    if not stable_versions:
        return normalize_initial_version(initial_version)

    major, minor, patch = max(stable_versions)
    return f"v{major}.{minor}.{patch + 1}"


def read_git_tags(repository: Path, *arguments: str) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(repository), "tag", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseTagError("could not read repository tags")
    return [line for line in completed.stdout.splitlines() if line]


def read_occupied_tags(path: Path) -> list[str]:
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReleaseTagError(f"could not read occupied release tags: {error}") from error
    return [line.strip() for line in contents.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--initial-version", default="0.1.0")
    parser.add_argument(
        "--occupied-tags-file",
        type=Path,
        help="newline-delimited tag names already used by GitHub Releases",
    )
    args = parser.parse_args()

    try:
        all_tags = read_git_tags(args.repository, "--list")
        if args.occupied_tags_file is not None:
            all_tags.extend(read_occupied_tags(args.occupied_tags_file))
        head_tags = read_git_tags(args.repository, "--points-at", "HEAD")
        tag = select_release_tag(all_tags, head_tags, args.initial_version)
    except ReleaseTagError as error:
        parser.error(str(error))

    print(tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
