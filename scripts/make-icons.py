#!/usr/bin/env python3
"""Build the production icon set from the official Muse logo.

Source: assets/muse-logo-source.ico — the favicon served by muse.ai itself
(blue brushstroke M on black), fetched 2026-10-26. Its frames are 16/32/48/
64/128 px, PNG-compressed.

Outputs:
  build/icon.ico       Multi-size Windows ICO: source frames 16/32/48/64/128
                       verbatim, a 24 px frame downscaled from the 128, and
                       a 256 px frame upscaled from the 128 (the source has
                       no 24 or 256; both are Lanczos resamples — see
                       BUILD_NOTES.md 0.2.2).
  build/icon.png       512 px PNG (Lanczos upscale of the 128 frame).
  assets/icon.png      Same 512 px PNG — window icon loaded by the app.
  assets/tray-16.png   Source 16 px frame, verbatim.
  assets/tray-32.png   Source 32 px frame, verbatim (tray @2x representation).

Requires Python 3 + Pillow on the build machine (build-time tool only;
nothing here ships in the app).
"""
import io
import struct
import sys
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assets" / "muse-logo-source.ico"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def extract_frames(ico_bytes):
    """Map size -> raw PNG bytes for every frame in an ICO file."""
    reserved, typ, count = struct.unpack_from("<HHH", ico_bytes, 0)
    if reserved != 0 or typ != 1:
        raise ValueError("not an ICO file")
    frames = {}
    for i in range(count):
        w, h, _colors, _res, _planes, _bits, size, offset = struct.unpack_from(
            "<BBBBHHII", ico_bytes, 6 + i * 16
        )
        blob = ico_bytes[offset : offset + size]
        if not blob.startswith(PNG_MAGIC):
            raise ValueError(f"frame {w}x{h} is not PNG-compressed; unsupported")
        frames[w or 256] = blob
    return frames


def png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def write_ico(path, frames):
    """frames: dict size -> PNG bytes. Writes a classic ICONDIR file."""
    sizes = sorted(frames)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    entries = b""
    data = b""
    offset = 6 + 16 * len(sizes)
    for s in sizes:
        blob = frames[s]
        entries += struct.pack(
            "<BBBBHHII",
            s % 256,  # 256 is stored as 0
            s % 256,
            0,
            0,
            1,
            32,
            len(blob),
            offset,
        )
        data += blob
        offset += len(blob)
    path.write_bytes(header + entries + data)


def main():
    frames = extract_frames(SOURCE.read_bytes())
    print("source frames:", sorted(frames))
    for needed in (16, 32, 48, 64, 128):
        if needed not in frames:
            sys.exit(f"source ICO is missing its {needed}px frame")

    img128 = Image.open(io.BytesIO(frames[128])).convert("RGBA")

    out = dict(frames)  # 16/32/48/64/128 verbatim
    out[24] = png_bytes(img128.resize((24, 24), Image.LANCZOS))
    out[256] = png_bytes(img128.resize((256, 256), Image.LANCZOS))
    write_ico(ROOT / "build" / "icon.ico", out)

    png512 = png_bytes(img128.resize((512, 512), Image.LANCZOS))
    (ROOT / "build" / "icon.png").write_bytes(png512)
    (ROOT / "assets" / "icon.png").write_bytes(png512)
    (ROOT / "assets" / "tray-16.png").write_bytes(frames[16])
    (ROOT / "assets" / "tray-32.png").write_bytes(frames[32])
    print("wrote: build/icon.ico (16/24/32/48/64/128/256), build/icon.png (512),")
    print("       assets/icon.png (512), assets/tray-16.png, assets/tray-32.png")


if __name__ == "__main__":
    main()
