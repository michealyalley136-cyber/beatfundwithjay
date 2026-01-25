from __future__ import annotations

from pathlib import Path
import sys


SVG_PATH = Path("static/brand/BeatFund_IconOnly_TightRounded.svg")
OUTPUT_DIR = Path("static/icons")

ICON_SIZES = {
    "icon-192.png": 192,
    "icon-512.png": 512,
    "icon-180.png": 180,
    "favicon-32.png": 32,
    "favicon-16.png": 16,
}


def _render_with_cairosvg(svg_bytes: bytes) -> None:
    import cairosvg  # type: ignore

    for name, size in ICON_SIZES.items():
        out_path = OUTPUT_DIR / name
        cairosvg.svg2png(
            bytestring=svg_bytes,
            output_width=size,
            output_height=size,
            write_to=str(out_path),
        )


def _render_with_svglib(svg_path: Path) -> None:
    from svglib.svglib import svg2rlg  # type: ignore
    from reportlab.graphics import renderPM  # type: ignore

    drawing = svg2rlg(str(svg_path))
    for name, size in ICON_SIZES.items():
        scale = size / max(drawing.width, drawing.height)
        drawing_copy = svg2rlg(str(svg_path))
        drawing_copy.scale(scale, scale)
        drawing_copy.width *= scale
        drawing_copy.height *= scale
        renderPM.drawToFile(drawing_copy, str(OUTPUT_DIR / name), fmt="PNG")


def main() -> int:
    if not SVG_PATH.exists():
        print(f"Missing SVG: {SVG_PATH}")
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    svg_bytes = SVG_PATH.read_bytes()

    try:
        _render_with_cairosvg(svg_bytes)
        print("Generated icons with cairosvg.")
        return 0
    except Exception:
        pass

    try:
        _render_with_svglib(SVG_PATH)
        print("Generated icons with svglib/reportlab.")
        return 0
    except Exception as exc:
        print(f"Failed to generate icons: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
