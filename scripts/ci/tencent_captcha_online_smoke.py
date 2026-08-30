#!/usr/bin/env python3
"""Optional authorized online smoke for Obscura's Tencent slider capture.

The live endpoint is intentionally not exercised by normal CI.  This script
can either drive an Obscura binary or inspect an existing resource archive.  A
page that does not materialize a Tencent slider is a clear SKIP; once a slider
is visible, missing frame/image/archive evidence is a failure.

Only a sanitized JSON report is written.  Signed asset URLs and response
bodies remain in the disposable archive directory supplied by the caller.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit
import zlib


DEFAULT_URL = "https://wiki.smzdm.com/p/z606zqm/"
MAX_IMAGE_BYTES = 16 * 1024 * 1024
MAX_DIMENSION = 8192
MAX_PIXELS = 16_777_216
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class SmokeError(RuntimeError):
    pass


def allowed_tencent_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    return (
        host
        in {
            "captcha.gtimg.com",
            "t.captcha.qq.com",
            "captcha.qcloud.com",
            "cloudcachetci.com",
        }
        or host.endswith(".captcha.qcloud.com")
        or host.endswith(".cloudcachetci.com")
    )


def allowed_tencent_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and (port is None or port == 443)
        and allowed_tencent_host(host)
    )


def slider_transport_url(value: Any) -> bool:
    if not isinstance(value, str) or not allowed_tencent_url(value):
        return False
    path = urlsplit(value).path.lower()
    return path.startswith("/cap_union_new_getcapbysig") or "/static/template/drag_" in path


def safe_archive_path(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not relative or ".." in candidate.parts:
        raise SmokeError("archive manifest contains an unsafe relative path")
    root_real = root.resolve()
    unresolved = root / candidate
    if unresolved.is_symlink():
        raise SmokeError("archive manifest refers to a symbolic link")
    path = unresolved.resolve()
    try:
        path.relative_to(root_real)
    except ValueError as error:
        raise SmokeError("archive manifest path escapes the archive directory") from error
    if not path.is_file():
        raise SmokeError(f"archive file is missing: {candidate.as_posix()}")
    return path


def read_limited(path: Path, limit: int = MAX_IMAGE_BYTES) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise SmokeError(f"archived image has an invalid byte length: {size}")
    data = path.read_bytes()
    if len(data) != size:
        raise SmokeError("archived image changed while it was being checked")
    return data


def verify_asset(root: Path, asset: dict[str, Any]) -> tuple[Path, bytes]:
    path = safe_archive_path(root, string_field(asset, "path"))
    data = read_limited(path)
    expected_bytes = asset.get("bytes")
    if (
        isinstance(expected_bytes, bool)
        or not isinstance(expected_bytes, int)
        or expected_bytes != len(data)
    ):
        raise SmokeError("archived image length does not match manifest")
    digest = hashlib.sha256(data).hexdigest()
    if asset.get("sha256") != digest:
        raise SmokeError("archived image digest does not match manifest")
    return path, data


def string_field(value: dict[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise SmokeError(f"manifest field {name!r} is missing or invalid")
    return result


def parse_css(style: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for declaration in style.split(";"):
        if ":" not in declaration:
            continue
        name, value = declaration.split(":", 1)
        name = name.strip().lower()
        if name:
            result[name] = value.strip()
    return result


CSS_URL_RE = re.compile(r"^url\(\s*(['\"]?)(.*?)\1\s*\)$", re.IGNORECASE)
PX_RE = re.compile(r"^-?(?:\d+(?:\.\d*)?|\.\d+)px$", re.IGNORECASE)


def css_url(value: str | None) -> str | None:
    if not value or value.lower() == "none":
        return None
    match = CSS_URL_RE.match(value.strip())
    return match.group(2) if match else None


def css_px(value: str | None) -> float | None:
    if value is None or not PX_RE.match(value.strip()):
        return None
    result = float(value[:-2])
    return result if math.isfinite(result) else None


def css_pair(
    style: dict[str, str],
    shorthand: str,
    x_name: str,
    y_name: str,
) -> tuple[float | None, float | None]:
    x_value = css_px(style.get(x_name))
    y_value = css_px(style.get(y_name))
    parts = style.get(shorthand, "").split()
    if x_value is None and parts:
        x_value = css_px(parts[0])
    if y_value is None and len(parts) > 1:
        y_value = css_px(parts[1])
    return x_value, y_value


class ChallengeHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.background: dict[str, Any] | None = None
        self.foregrounds: list[dict[str, Any]] = []
        self.has_challenge_marker = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        classes = set(values.get("class", "").split())
        element_id = values.get("id", "")
        if element_id == "slideBg" or "tc-fg-item" in classes:
            self.has_challenge_marker = True
        if element_id != "slideBg" and "tc-fg-item" not in classes:
            return

        style = parse_css(values.get("style", ""))
        source = values.get("src") if tag.lower() == "img" else None
        source = source or css_url(style.get("background-image"))
        width = css_px(style.get("width"))
        height = css_px(style.get("height"))
        position_x, position_y = css_pair(
            style, "background-position", "background-position-x", "background-position-y"
        )
        size_x, size_y = css_pair(
            style,
            "background-size",
            "background-size-x",
            "background-size-y",
        )
        record = {
            "kind": "image" if tag.lower() == "img" and values.get("src") else "css",
            "url": source,
            "width": width,
            "height": height,
            "position_x": position_x,
            "position_y": position_y,
            "size_x": size_x,
            "size_y": size_y,
        }
        if element_id == "slideBg":
            record["kind"] = "background"
            self.background = record
        else:
            self.foregrounds.append(record)


def choose_piece(background: dict[str, Any], foregrounds: list[dict[str, Any]]) -> dict[str, Any]:
    bg_width = background.get("width")
    bg_height = background.get("height")
    if not finite_positive(bg_width) or not finite_positive(bg_height):
        raise SmokeError("Tencent background has no usable CSS dimensions")
    candidates = []
    for item in foregrounds:
        width = item.get("width")
        height = item.get("height")
        if not finite_positive(width) or not finite_positive(height) or not item.get("url"):
            continue
        aspect = width / height
        css_ready = item.get("kind") == "image" or all(
            math.isfinite(value) if isinstance(value, (float, int)) else False
            for value in (
                item.get("position_x"),
                item.get("position_y"),
                item.get("size_x"),
                item.get("size_y"),
            )
        )
        if (
            css_ready
            and 0.85 <= aspect <= 1.18
            and width >= 16.0
            and height >= 16.0
            and width < bg_width * 0.75
            and height < bg_height * 0.9
        ):
            candidates.append(item)
    if not candidates:
        raise SmokeError("Tencent slider has no square puzzle foreground")
    if len(candidates) != 1:
        raise SmokeError("Tencent slider has multiple plausible puzzle foregrounds")
    return candidates[0]


def finite_positive(value: Any) -> bool:
    return isinstance(value, (float, int)) and math.isfinite(value) and value > 0


def png_chunks(data: bytes) -> tuple[dict[str, int], bytes]:
    if not data.startswith(PNG_SIGNATURE):
        raise SmokeError("Tencent foreground sprite is not a PNG")
    offset = len(PNG_SIGNATURE)
    header: dict[str, int] | None = None
    compressed = bytearray()
    saw_end = False
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        start = offset + 8
        end = start + length
        if end + 4 > len(data):
            raise SmokeError("Tencent PNG sprite is truncated")
        payload = data[start:end]
        expected_crc = struct.unpack(">I", data[end : end + 4])[0]
        if binascii.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            raise SmokeError("Tencent PNG sprite has an invalid CRC")
        if kind == b"IHDR":
            if length != 13 or header is not None:
                raise SmokeError("Tencent PNG sprite has an invalid header")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            header = {
                "width": width,
                "height": height,
                "depth": depth,
                "color": color,
                "compression": compression,
                "filtering": filtering,
                "interlace": interlace,
            }
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            saw_end = True
            break
        offset = end + 4
    if header is None or not compressed or not saw_end:
        raise SmokeError("Tencent PNG sprite is incomplete")
    return header, bytes(compressed)


def validate_dimensions(width: int, height: int) -> None:
    if (
        width <= 0
        or height <= 0
        or width > MAX_DIMENSION
        or height > MAX_DIMENSION
        or width * height > MAX_PIXELS
    ):
        raise SmokeError("Tencent image dimensions exceed smoke-test safety limits")


def paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def decode_png_rgba(data: bytes) -> tuple[int, int, bytes]:
    header, compressed = png_chunks(data)
    width = header["width"]
    height = header["height"]
    validate_dimensions(width, height)
    if (
        header["depth"] != 8
        or header["color"] not in {2, 6}
        or header["compression"] != 0
        or header["filtering"] != 0
        or header["interlace"] != 0
    ):
        raise SmokeError("Tencent PNG sprite uses an unsupported pixel layout")
    channels = 4 if header["color"] == 6 else 3
    stride = width * channels
    expected = (stride + 1) * height
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(compressed, expected + 1)
    except zlib.error as error:
        raise SmokeError("Tencent PNG sprite cannot be decompressed") from error
    if (
        len(raw) != expected
        or not decompressor.eof
        or decompressor.unconsumed_tail
        or decompressor.unused_data
    ):
        raise SmokeError("Tencent PNG sprite has an unexpected decoded length")

    decoded = bytearray(stride * height)
    for row in range(height):
        source = row * (stride + 1)
        filter_kind = raw[source]
        if filter_kind > 4:
            raise SmokeError("Tencent PNG sprite uses an invalid row filter")
        for column in range(stride):
            value = raw[source + 1 + column]
            target = row * stride + column
            left = decoded[target - channels] if column >= channels else 0
            above = decoded[target - stride] if row else 0
            upper_left = decoded[target - stride - channels] if row and column >= channels else 0
            if filter_kind == 1:
                value = (value + left) & 0xFF
            elif filter_kind == 2:
                value = (value + above) & 0xFF
            elif filter_kind == 3:
                value = (value + ((left + above) // 2)) & 0xFF
            elif filter_kind == 4:
                value = (value + paeth(left, above, upper_left)) & 0xFF
            decoded[target] = value
    if channels == 4:
        return width, height, bytes(decoded)
    rgba = bytearray(width * height * 4)
    for pixel in range(width * height):
        rgba[pixel * 4 : pixel * 4 + 3] = decoded[pixel * 3 : pixel * 3 + 3]
        rgba[pixel * 4 + 3] = 255
    return width, height, bytes(rgba)


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def encode_png_rgba(width: int, height: int, pixels: bytes) -> bytes:
    if len(pixels) != width * height * 4:
        raise SmokeError("cannot encode puzzle piece with an invalid pixel length")
    rows = b"".join(b"\x00" + pixels[row * width * 4 : (row + 1) * width * 4] for row in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        PNG_SIGNATURE
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(rows, 9))
        + png_chunk(b"IEND", b"")
    )


def image_dimensions(data: bytes) -> tuple[int, int, str]:
    if data.startswith(PNG_SIGNATURE):
        header, _ = png_chunks(data)
        width, height = header["width"], header["height"]
        validate_dimensions(width, height)
        return width, height, "png"
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 4 <= len(data):
            while offset < len(data) and data[offset] == 0xFF:
                offset += 1
            if offset >= len(data):
                break
            marker = data[offset]
            offset += 1
            if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
                continue
            if offset + 2 > len(data):
                break
            length = struct.unpack(">H", data[offset : offset + 2])[0]
            if length < 2 or offset + length > len(data):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
                if length < 7:
                    break
                height, width = struct.unpack(">HH", data[offset + 3 : offset + 7])
                validate_dimensions(width, height)
                return width, height, "jpg"
            offset += length
    raise SmokeError("Tencent background is not a supported PNG or JPEG image")


def rounded_edge(value: float) -> int:
    if not math.isfinite(value) or value < 0 or value > 0xFFFFFFFF:
        raise SmokeError("CSS sprite maps outside valid source pixels")
    rounded = math.floor(value + 0.5)
    if abs(value - rounded) > 0.05:
        raise SmokeError("CSS sprite edge does not align closely enough with source pixels")
    return rounded


def extract_piece(sprite_data: bytes, layout: dict[str, Any]) -> tuple[bytes, dict[str, int]]:
    source_width, source_height, rgba = decode_png_rgba(sprite_data)
    if layout.get("kind") == "image":
        return encode_png_rgba(source_width, source_height, rgba), {
            "x": 0,
            "y": 0,
            "width": source_width,
            "height": source_height,
        }
    position_x = layout.get("position_x")
    position_y = layout.get("position_y")
    size_x = layout.get("size_x")
    size_y = layout.get("size_y")
    width = layout.get("width")
    height = layout.get("height")
    geometry = (position_x, position_y, width, height)
    if not all(
        isinstance(value, (int, float)) and math.isfinite(value) for value in geometry
    ):
        raise SmokeError("CSS sprite does not expose absolute pixel geometry")
    if not finite_positive(size_x) or not finite_positive(size_y):
        raise SmokeError("CSS sprite does not expose a positive pixel background size")
    scale_x = source_width / size_x
    scale_y = source_height / size_y
    x = rounded_edge(-position_x * scale_x)
    y = rounded_edge(-position_y * scale_y)
    right = rounded_edge((-position_x + width) * scale_x)
    bottom = rounded_edge((-position_y + height) * scale_y)
    if right <= x or bottom <= y or right > source_width or bottom > source_height:
        raise SmokeError("CSS sprite crop lies outside the foreground source")
    crop_width = right - x
    crop_height = bottom - y
    output = bytearray(crop_width * crop_height * 4)
    for row in range(crop_height):
        source_start = ((y + row) * source_width + x) * 4
        target_start = row * crop_width * 4
        output[target_start : target_start + crop_width * 4] = rgba[
            source_start : source_start + crop_width * 4
        ]
    return encode_png_rgba(crop_width, crop_height, bytes(output)), {
        "x": x,
        "y": y,
        "width": crop_width,
        "height": crop_height,
    }


def find_asset(
    assets: list[dict[str, Any]], source_url: str, frame_id: int
) -> dict[str, Any]:
    if not allowed_tencent_url(source_url):
        raise SmokeError("Tencent slider image URL is outside the expected HTTPS hosts")
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict)
        and not isinstance(asset.get("frame_id"), bool)
        and asset.get("frame_id") == frame_id
        and asset.get("resource_type") == "image"
        and source_url in {asset.get("request_url"), asset.get("final_url")}
    ]
    if not matches:
        raise SmokeError("Tencent slider image has no archived frame-owned response")
    identities = {(asset.get("sha256"), asset.get("bytes")) for asset in matches}
    if len(identities) != 1:
        raise SmokeError("Tencent slider image has conflicting archived responses")
    return matches[0]


def run_matcher(
    binary: Path,
    piece: Path,
    background: Path,
    background_size: tuple[int, int],
) -> dict[str, Any]:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SmokeError("ai_slide_matcher path is not an executable file")
    with tempfile.TemporaryFile() as stdout:
        result = subprocess.run(
            [
                str(binary),
                "match",
                "--piece-file",
                str(piece),
                "--background-file",
                str(background),
                "--algorithm",
                "gray",
            ],
            stdout=stdout,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        output_bytes = stdout.tell()
        if output_bytes > 4096:
            raise SmokeError("ai_slide_matcher emitted an oversized response")
        stdout.seek(0)
        try:
            output = stdout.read().decode("utf-8")
        except UnicodeDecodeError as error:
            raise SmokeError("ai_slide_matcher response is not UTF-8") from error
    if result.returncode != 0:
        raise SmokeError(f"ai_slide_matcher exited with status {result.returncode}")
    try:
        coordinate = json.loads(output.strip())
    except json.JSONDecodeError as error:
        raise SmokeError("ai_slide_matcher did not emit a JSON coordinate") from error
    if (
        not isinstance(coordinate, list)
        or len(coordinate) != 2
        or any(isinstance(value, bool) or not isinstance(value, int) for value in coordinate)
    ):
        raise SmokeError("ai_slide_matcher coordinate has an invalid shape")
    width, height = background_size
    if not (0 <= coordinate[0] < width and 0 <= coordinate[1] < height):
        raise SmokeError("ai_slide_matcher coordinate lies outside the background image")
    return {
        "status": "pass",
        "algorithm": "gray",
        "coordinate": coordinate,
        "within_background": True,
    }


def inspect_archive(archive: Path, derived: Path, matcher: Path | None) -> dict[str, Any]:
    manifest_path = archive / "manifest.json"
    if not manifest_path.is_file():
        raise SmokeError("Obscura did not write an asset archive manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SmokeError("Obscura asset archive manifest is unreadable") from error
    version = manifest.get("version") if isinstance(manifest, dict) else None
    if isinstance(version, bool) or version != 1:
        raise SmokeError("Obscura asset archive manifest version is unsupported")
    frames = manifest.get("frames")
    assets = manifest.get("assets")
    if not isinstance(frames, list) or not isinstance(assets, list):
        raise SmokeError("Obscura asset archive manifest has invalid frame or asset records")

    tencent_frames: list[tuple[dict[str, Any], ChallengeHTMLParser]] = []
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        frame_url = frame.get("url")
        if not isinstance(frame_url, str) or not allowed_tencent_url(frame_url):
            continue
        parser = ChallengeHTMLParser()
        frame_path = safe_archive_path(archive, string_field(frame, "path"))
        try:
            parser.feed(frame_path.read_text(encoding="utf-8", errors="replace"))
            parser.close()
        except Exception as error:
            raise SmokeError("serialized Tencent frame cannot be parsed") from error
        tencent_frames.append((frame, parser))

    visual_frames = [
        (frame, parser)
        for frame, parser in tencent_frames
        if parser.has_challenge_marker
    ]
    if not visual_frames:
        transport_evidence = any(
            slider_transport_url(frame.get("url"))
            for frame, _parser in tencent_frames
        ) or any(
            isinstance(asset, dict)
            and (
                slider_transport_url(asset.get("request_url"))
                or slider_transport_url(asset.get("final_url"))
            )
            for asset in assets
        )
        if transport_evidence:
            raise SmokeError(
                "Tencent slider responses were present, but no serialized slider iframe materialized"
            )
        reason = (
            "Tencent non-slider frame loaded, but no slider challenge materialized"
            if tencent_frames
            else "target did not return a Tencent slider challenge"
        )
        return {
            "status": "skip",
            "reason": reason,
            "manifest_complete": bool(manifest.get("complete")),
            "frame_count": len(frames),
            "asset_count": len(assets),
        }
    if len(visual_frames) != 1:
        raise SmokeError("archive contains multiple materialized Tencent slider frames")
    frame, parser = visual_frames[0]
    if parser.background is None or not parser.background.get("url"):
        raise SmokeError("Tencent slider frame is missing its background image layout")
    piece_layout = choose_piece(parser.background, parser.foregrounds)
    frame_id = frame.get("frame_id")
    if isinstance(frame_id, bool) or not isinstance(frame_id, int) or frame_id <= 0:
        raise SmokeError("Tencent slider frame has an invalid frame id")
    if manifest.get("complete") is not True:
        raise SmokeError("Tencent slider was present, but Obscura marked the archive incomplete")

    background_asset = find_asset(assets, parser.background["url"], frame_id)
    foreground_asset = find_asset(assets, piece_layout["url"], frame_id)
    _, background_data = verify_asset(archive, background_asset)
    _, foreground_data = verify_asset(archive, foreground_asset)
    background_width, background_height, background_extension = image_dimensions(background_data)
    piece_data, crop = extract_piece(foreground_data, piece_layout)

    if derived.exists():
        raise SmokeError("derived output directory must not already exist")
    derived.mkdir(parents=True)
    background_path = derived / f"background.{background_extension}"
    piece_path = derived / "piece.png"
    background_path.write_bytes(background_data)
    piece_path.write_bytes(piece_data)

    matcher_result: dict[str, Any] = {"status": "not_requested"}
    if matcher is not None:
        matcher_result = run_matcher(
            matcher,
            piece_path,
            background_path,
            (background_width, background_height),
        )
    return {
        "status": "pass",
        "manifest_complete": True,
        "frame": {"frame_id": frame_id, "host": urlsplit(string_field(frame, "url")).hostname},
        "background": {
            "path": background_path.name,
            "width": background_width,
            "height": background_height,
            "bytes": len(background_data),
            "sha256": hashlib.sha256(background_data).hexdigest(),
        },
        "foreground_sprite": {
            "archived": True,
            "bytes": len(foreground_data),
            "sha256": hashlib.sha256(foreground_data).hexdigest(),
        },
        "piece": {
            "path": piece_path.name,
            "width": crop["width"],
            "height": crop["height"],
            "sprite_crop": crop,
            "sha256": hashlib.sha256(piece_data).hexdigest(),
        },
        "matcher": matcher_result,
    }


def capture_archive(args: argparse.Namespace, archive: Path) -> int:
    if archive.exists():
        raise SmokeError("capture archive directory must not already exist")
    binary = Path(args.obscura)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SmokeError("Obscura path is not an executable file")
    command = [str(binary)]
    if args.stealth:
        command.append("--stealth")
    command.extend(
        [
            "fetch",
            args.url,
            "--dump",
            "assets",
            "--assets-dir",
            str(archive),
            "--assets-max-bytes",
            str(64 * 1024 * 1024),
            "--assets-max-resources",
            "512",
            "--wait-until",
            "capture-ready",
            "--wait",
            str(args.wait),
            "--timeout",
            str(args.timeout),
            "--quiet",
        ]
    )
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=args.timeout + args.wait * 6 + 60,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeError("Obscura online capture exceeded the process deadline") from error
    return completed.returncode


def write_report(path: Path | None, report: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def attach_capture_result(
    report: dict[str, Any], capture_exit: int | None
) -> dict[str, Any]:
    """Attach capture status and reject every failed live-capture process.

    Archive-only inspection has no capture process and therefore uses None.
    For a live run, a materialized challenge and a legitimate no-challenge
    skip are both meaningful only when Obscura itself exited successfully.
    """
    report["capture_exit_code"] = capture_exit
    if capture_exit is not None and capture_exit != 0:
        raise SmokeError(f"Obscura capture exited with status {capture_exit}")
    return report


def build_fixture(
    root: Path,
    include_challenge: bool,
    include_piece_asset: bool = True,
) -> Path:
    archive = root / "archive"
    (archive / "frames").mkdir(parents=True)
    (archive / "resources").mkdir()
    frames: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    if include_challenge:
        background_url = "https://t.captcha.qq.com/image?img_index=1&test=offline"
        foreground_url = "https://t.captcha.qq.com/image?img_index=0&test=offline"
        html = f'''<div id="tcWrap" class="tc-captcha">
<div id="slideBg" style="width:100px;height:60px;background-image:url({background_url})"></div>
<div class="tc-fg-item" style="width:20px;height:20px;
background-image:url({foreground_url});background-position:-10px -10px;
background-size:40px 30px"></div>
</div>'''
        (archive / "frames/0000.html").write_text(html, encoding="utf-8")
        frames.append(
            {
                "frame_id": 7,
                "url": "https://captcha.gtimg.com/static/template/drag_ele.test.html",
                "path": "frames/0000.html",
            }
        )
        background_pixels = bytes([20, 30, 40, 255]) * (120 * 80)
        foreground_pixels = bytes([90, 80, 70, 200]) * (80 * 60)
        records = [
            (
                background_url,
                "resources/background.png",
                encode_png_rgba(120, 80, background_pixels),
            ),
            (
                foreground_url,
                "resources/foreground.png",
                encode_png_rgba(80, 60, foreground_pixels),
            ),
        ]
        if not include_piece_asset:
            records.pop()
        for url, relative, data in records:
            (archive / relative).write_bytes(data)
            assets.append(
                {
                    "request_url": url,
                    "final_url": url,
                    "resource_type": "image",
                    "frame_id": 7,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "path": relative,
                }
            )
    manifest = {
        "version": 1,
        "complete": True,
        "frames": frames,
        "assets": assets,
    }
    (archive / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return archive


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="obscura-tcaptcha-selftest-") as temp:
        root = Path(temp)
        no_challenge = build_fixture(root / "skip", False)
        skipped = inspect_archive(no_challenge, root / "skip-derived", None)
        assert skipped["status"] == "skip"
        # A no-challenge archive is a SKIP only after a successful capture.
        # The old main-path condition checked non-zero exits for PASS reports
        # only, allowing this exact combination to return process status 0.
        try:
            attach_capture_result(dict(skipped), 23)
        except SmokeError as error:
            assert "status 23" in str(error)
        else:
            raise AssertionError("failed capture was accepted as a slider skip")
        assert attach_capture_result(dict(skipped), 0)["status"] == "skip"
        assert attach_capture_result(dict(skipped), None)["status"] == "skip"

        # Exercise the CLI boundary too: a fake capture writes a perfectly
        # inspectable no-challenge archive and then exits non-zero. The smoke
        # process must report FAIL/1, never SKIP/0.
        fake_obscura = root / "fake-obscura"
        fake_obscura.write_text(
            """#!/usr/bin/env python3
import json
from pathlib import Path
import sys

archive = Path(sys.argv[sys.argv.index("--assets-dir") + 1])
archive.mkdir(parents=True)
(archive / "manifest.json").write_text(json.dumps({
    "version": 1, "complete": True, "frames": [], "assets": []
}), encoding="utf-8")
raise SystemExit(23)
""",
            encoding="utf-8",
        )
        fake_obscura.chmod(0o755)
        failed_report = root / "failed-capture-report.json"
        failed_run = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--obscura",
                str(fake_obscura),
                "--work-dir",
                str(root / "failed-capture"),
                "--report",
                str(failed_report),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        assert failed_run.returncode == 1
        failed = json.loads(failed_report.read_text(encoding="utf-8"))
        assert failed["status"] == "fail"
        assert failed["capture_exit_code"] == 23
        assert "status 23" in failed["reason"]

        challenge = build_fixture(root / "pass", True)
        passed = inspect_archive(challenge, root / "pass-derived", None)
        assert passed["status"] == "pass"
        assert passed["piece"]["sprite_crop"] == {"x": 20, "y": 20, "width": 40, "height": 40}
        assert passed["background"]["width"] == 120

        # Repeated cache/body records are valid when they identify the same
        # archived response bytes.
        manifest_path = challenge / "manifest.json"
        duplicate_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        duplicate_manifest["assets"].append(dict(duplicate_manifest["assets"][0]))
        manifest_path.write_text(json.dumps(duplicate_manifest), encoding="utf-8")
        duplicated = inspect_archive(challenge, root / "duplicate-derived", None)
        assert duplicated["status"] == "pass"

        missing = build_fixture(root / "missing", True, include_piece_asset=False)
        try:
            inspect_archive(missing, root / "missing-derived", None)
        except SmokeError:
            pass
        else:
            raise AssertionError("missing foreground response was accepted")

        transport_only = build_fixture(root / "transport-only", False)
        transport_manifest_path = transport_only / "manifest.json"
        transport_manifest = json.loads(
            transport_manifest_path.read_text(encoding="utf-8")
        )
        transport_manifest["assets"].append(
            {
                "request_url": "https://captcha.gtimg.com/static/template/drag_ele.test.html",
                "final_url": "https://captcha.gtimg.com/static/template/drag_ele.test.html",
                "resource_type": "document",
                "frame_id": 9,
                "bytes": 1,
                "sha256": "0" * 64,
                "path": "resources/not-read.html",
            }
        )
        transport_manifest_path.write_text(
            json.dumps(transport_manifest), encoding="utf-8"
        )
        try:
            inspect_archive(transport_only, root / "transport-derived", None)
        except SmokeError:
            pass
        else:
            raise AssertionError("slider transport evidence without an iframe was skipped")
    print("ONLINE_SMOKE_SELF_TEST_PASS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--obscura", help="Obscura executable used to perform a new online capture")
    source.add_argument("--archive", type=Path, help="existing Obscura asset archive to inspect")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="new or existing empty work directory for a live capture",
    )
    parser.add_argument(
        "--derived-dir",
        type=Path,
        help="new directory for background and piece outputs",
    )
    parser.add_argument("--report", type=Path, help="write a sanitized JSON report")
    parser.add_argument("--matcher", type=Path, help="optional ai_slide_matcher executable")
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--wait", type=int, default=8)
    parser.add_argument("--stealth", action="store_true")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic offline checks",
    )
    args = parser.parse_args()
    if args.self_test:
        return args
    if not args.obscura and args.archive is None:
        parser.error("one of --obscura or --archive is required")
    if args.obscura and args.work_dir is None:
        parser.error("--work-dir is required with --obscura")
    if args.timeout <= 0 or args.wait < 0:
        parser.error("--timeout must be positive and --wait must be non-negative")
    return args


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    capture_exit: int | None = None
    try:
        if args.obscura:
            work = args.work_dir
            work.mkdir(parents=True, exist_ok=True)
            archive = work / "archive"
            derived = args.derived_dir or work / "derived"
            capture_exit = capture_archive(args, archive)
        else:
            archive = args.archive
            derived = args.derived_dir or archive.parent / f"{archive.name}-tcaptcha-derived"
        report = attach_capture_result(
            inspect_archive(archive, derived, args.matcher), capture_exit
        )
        write_report(args.report, report)
        if report["status"] == "skip":
            print(f"ONLINE_SMOKE_SKIP: {report['reason']}")
        else:
            matcher_status = report["matcher"]["status"]
            print(
                "ONLINE_SMOKE_PASS: Tencent iframe, background, and puzzle piece are archived; "
                f"matcher={matcher_status}"
            )
        return 0
    except (OSError, SmokeError, subprocess.SubprocessError) as error:
        failure = {"status": "fail", "reason": str(error), "capture_exit_code": capture_exit}
        write_report(args.report, failure)
        print(f"ONLINE_SMOKE_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
