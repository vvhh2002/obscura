#!/usr/bin/env python3
"""Validate and rebuild a public-safe ai_slide_matcher smoke manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Iterable


MAX_INPUT_BYTES = 64 * 1024
MATRIX_TARGETS = frozenset(
    {
        "linux-x64-musl",
        "linux-arm64-musl",
        "macos-x64",
        "macos-arm64",
        "windows-x64",
    }
)

# SemVer 2.0.0. Numeric pre-release identifiers may not have leading zeroes;
# build identifiers may. Restricting the grammar to ASCII also prevents
# lookalike characters from entering a public artifact name or report.
SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*)|"
    r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r")(?:\.(?:"
    r"(?:0|[1-9][0-9]*)|"
    r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)


class SmokeManifestError(ValueError):
    """Raised when a private smoke manifest is not exactly allowlisted."""


def _case(
    name: str, code: int, stdout: str, category: str | None
) -> dict[str, object]:
    return {
        "name": name,
        "code": code,
        "stdout": stdout,
        "category": category,
    }


def expected_cases(version: str) -> list[dict[str, object]]:
    """Build the only smoke case list authorized for public output."""

    return [
        _case("version", 0, f"ai_slide_matcher {version}\n", None),
        _case("match-gray", 0, "[49,35]\n", None),
        _case(
            "adapter-tianai",
            0,
            '{"adapter":"tianai","bgImageWidth":192,"bgImageHeight":144,'
            '"templateImageWidth":48,"templateImageHeight":40,"targetX":74,'
            '"targetY":50,"trackDeltaX":74,"percentage":0.3854166666666667}\n',
            None,
        ),
        _case(
            "adapter-gocaptcha",
            0,
            '{"adapter":"gocaptcha","x":74,"y":50,"dx":10,"dy":20,'
            '"moveX":64,"moveY":30}\n',
            None,
        ),
        _case(
            "adapter-aj-captcha",
            0,
            '{"adapter":"aj-captcha","point":{"x":119,"y":5}}\n',
            None,
        ),
        _case(
            "adapter-slider-captcha-js",
            0,
            '{"adapter":"slider-captcha-js","x":69}\n',
            None,
        ),
        _case("compare", 0, "[48,35]\n", None),
        _case("no-match", 5, "", "NO_MATCH"),
        _case("bad-input", 3, "", "INPUT"),
        _case("incompatible-dimensions", 4, "", "INCOMPATIBLE"),
        _case("usage", 2, "", "USAGE"),
    ]


def canonical_manifest(target: str, version: str) -> dict[str, object]:
    """Return a new manifest made exclusively from public constants."""

    validate_target(target)
    validate_version(version)
    return {"schema": 1, "target": target, "cases": expected_cases(version)}


def render_canonical_manifest(target: str, version: str) -> str:
    """Serialize the public manifest deterministically."""

    return json.dumps(
        canonical_manifest(target, version),
        ensure_ascii=True,
        indent=2,
        separators=(",", ": "),
    ) + "\n"


def validate_target(target: str) -> None:
    if target not in MATRIX_TARGETS:
        raise SmokeManifestError("target is not an allowed release matrix id")


def validate_version(version: str) -> None:
    if not isinstance(version, str) or SEMVER_RE.fullmatch(version) is None:
        raise SmokeManifestError("version is not valid SemVer")


def _object_without_duplicate_keys(
    pairs: Iterable[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SmokeManifestError("manifest contains a duplicate object key")
        result[key] = value
    return result


def load_manifest(path: Path) -> object:
    """Load bounded UTF-8 JSON without exposing its contents in errors."""

    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise SmokeManifestError("manifest is oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SmokeManifestError("manifest is not UTF-8") from error
    try:
        return json.loads(text, object_pairs_hook=_object_without_duplicate_keys)
    except json.JSONDecodeError as error:
        raise SmokeManifestError("manifest is not valid JSON") from error
    except RecursionError as error:
        raise SmokeManifestError("manifest nesting is too deep") from error


def validate_manifest(data: object, target: str, version: str) -> None:
    """Require an exact, typed match with the allowlisted smoke contract."""

    expected = canonical_manifest(target, version)
    if not isinstance(data, dict):
        raise SmokeManifestError("manifest root must be an object")
    if set(data) != {"schema", "target", "cases"}:
        raise SmokeManifestError("manifest root keys differ from the allowlist")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise SmokeManifestError("manifest schema differs from the allowlist")
    if type(data["target"]) is not str or data["target"] != target:
        raise SmokeManifestError("manifest target differs from the expected matrix id")

    cases = data["cases"]
    expected_case_list = expected["cases"]
    if not isinstance(cases, list) or len(cases) != 11:
        raise SmokeManifestError("manifest must contain exactly 11 cases")
    assert isinstance(expected_case_list, list)
    for index, (case, expected_case) in enumerate(zip(cases, expected_case_list)):
        if not isinstance(case, dict):
            raise SmokeManifestError(f"case {index} must be an object")
        if set(case) != {"name", "code", "stdout", "category"}:
            raise SmokeManifestError(f"case {index} keys differ from the allowlist")
        if type(case["name"]) is not str:
            raise SmokeManifestError(f"case {index} name has the wrong type")
        if type(case["code"]) is not int:
            raise SmokeManifestError(f"case {index} code has the wrong type")
        if type(case["stdout"]) is not str:
            raise SmokeManifestError(f"case {index} stdout has the wrong type")
        if case["category"] is not None and type(case["category"]) is not str:
            raise SmokeManifestError(f"case {index} category has the wrong type")
        if case != expected_case:
            raise SmokeManifestError(f"case {index} content differs from the allowlist")


def sanitize_manifest(source: Path, destination: Path, target: str, version: str) -> None:
    """Validate private input, then write a fresh public canonical manifest."""

    data = load_manifest(source)
    validate_manifest(data, target, version)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise SmokeManifestError("manifest output directory is not a regular directory")
    with destination.open(
        "x",
        encoding="utf-8",
        newline="\n",
    ) as output:
        output.write(render_canonical_manifest(target, version))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and rebuild one public-safe matcher smoke manifest."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    try:
        sanitize_manifest(args.input, args.output, args.target, args.version)
    except (OSError, SmokeManifestError):
        # Never include input JSON, parsed values, or underlying exceptions in a
        # public Actions log. A validation failure is sufficient diagnostics.
        print("MATCHER_SMOKE_SANITIZE_FAIL: manifest rejected", file=sys.stderr)
        return 1

    print("MATCHER_SMOKE_SANITIZE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
