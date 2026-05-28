"""
Generate assets/icon.png (and a 64x64 favicon) from a Pillow-drawn version
of assets/icon.svg. Run once after editing the SVG:

    python assets/generate_icon.py

Re-run if you change the design. Kept as a script (not auto-run) so the
build remains offline / reproducible.
"""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


SIZE = 512  # supersampled, downscaled to 256 for crisp edges
OUT = Path(__file__).resolve().parent

BG_OUTER = (2, 5, 9)
BG_INNER = (7, 19, 32)
BORDER = (10, 48, 80)
CYAN = (0, 212, 255)
GREEN = (0, 255, 157)


def find_font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont:
    for c in candidates:
        try:
            return ImageFont.truetype(c, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def draw_icon(s: int) -> Image.Image:
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img, "RGBA")

    # rounded plate with a soft radial-ish background
    plate = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    pd = ImageDraw.Draw(plate, "RGBA")
    radius = int(s * 0.172)
    pd.rounded_rectangle((8, 8, s - 8, s - 8), radius=radius,
                         fill=BG_OUTER, outline=BORDER, width=4)
    # inner glow
    inner = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    id_ = ImageDraw.Draw(inner, "RGBA")
    id_.ellipse((s * 0.18, s * 0.18, s * 0.82, s * 0.82),
                fill=BG_INNER + (180,))
    inner = inner.filter(ImageFilter.GaussianBlur(s * 0.06))
    plate = Image.alpha_composite(plate, inner)
    img = Image.alpha_composite(img, plate)
    d = ImageDraw.Draw(img, "RGBA")

    # subtle grid
    step = s // 8
    for x in range(step, s, step):
        d.line([(x, 0), (x, s)], fill=CYAN + (14,), width=1)
    for y in range(step, s, step):
        d.line([(0, y), (s, y)], fill=CYAN + (14,), width=1)

    cx = cy = s // 2

    # outer dashed ring
    R1 = int(s * 0.36)
    bbox1 = (cx - R1, cy - R1, cx + R1, cy + R1)
    for i in range(0, 360, 10):
        d.arc(bbox1, start=i, end=i + 4, fill=CYAN + (235,), width=4)

    # mid ring
    R2 = int(s * 0.305)
    d.ellipse((cx - R2, cy - R2, cx + R2, cy + R2),
              outline=CYAN + (160,), width=3)

    # inner ring
    R3 = int(s * 0.245)
    d.ellipse((cx - R3, cy - R3, cx + R3, cy + R3),
              outline=CYAN + (90,), width=2)

    # ring tick marks
    for ang in range(0, 360, 30):
        a = math.radians(ang - 90)
        x1 = cx + (R1 - 4) * math.cos(a)
        y1 = cy + (R1 - 4) * math.sin(a)
        x2 = cx + (R1 - 22) * math.cos(a)
        y2 = cy + (R1 - 22) * math.sin(a)
        d.line([(x1, y1), (x2, y2)], fill=CYAN + (220,), width=4)

    # corner crosshairs
    arm = int(s * 0.055)
    pad = int(s * 0.085)
    cl = GREEN + (235,)
    w = 5
    # top-left
    d.line([(pad, pad + arm), (pad, pad), (pad + arm, pad)], fill=cl, width=w)
    # top-right
    d.line([(s - pad - arm, pad), (s - pad, pad), (s - pad, pad + arm)],
           fill=cl, width=w)
    # bottom-right
    d.line([(s - pad, s - pad - arm), (s - pad, s - pad),
            (s - pad - arm, s - pad)], fill=cl, width=w)
    # bottom-left
    d.line([(pad + arm, s - pad), (pad, s - pad), (pad, s - pad - arm)],
           fill=cl, width=w)

    # central cryptex barrel
    bw = int(s * 0.39)
    bh = int(s * 0.28)
    bx0 = cx - bw // 2
    by0 = cy - bh // 2
    bx1 = cx + bw // 2
    by1 = cy + bh // 2
    d.rounded_rectangle((bx0, by0, bx1, by1), radius=int(s * 0.04),
                        fill=BG_OUTER, outline=CYAN, width=5)
    # ring divisions (4 letter slots)
    slots = 4
    for i in range(1, slots):
        x = bx0 + (bw * i) // slots
        d.line([(x, by0 + 4), (x, by1 - 4)],
               fill=CYAN + (180,), width=2)

    # end caps
    cap_w = int(s * 0.039)
    cap_h = int(bh * 0.78)
    cap_y0 = cy - cap_h // 2
    cap_y1 = cy + cap_h // 2
    d.rounded_rectangle((bx0 - cap_w, cap_y0, bx0, cap_y1),
                        radius=4, fill=BORDER, outline=CYAN, width=3)
    d.rounded_rectangle((bx1, cap_y0, bx1 + cap_w, cap_y1),
                        radius=4, fill=BORDER, outline=CYAN, width=3)

    # letters in slots: C  L  A  B  (A in cyan, others in green)
    glyph_font = find_font(
        [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
        ],
        size=int(bh * 0.55),
    )
    glyphs = ["C", "L", "A", "B"]
    glyph_colors = [GREEN, GREEN, CYAN, GREEN]
    for i, (g, col) in enumerate(zip(glyphs, glyph_colors)):
        slot_cx = bx0 + (bw * (2 * i + 1)) // (2 * slots)
        bbox = d.textbbox((0, 0), g, font=glyph_font)
        gw = bbox[2] - bbox[0]
        gh = bbox[3] - bbox[1]
        d.text((slot_cx - gw // 2 - bbox[0], cy - gh // 2 - bbox[1]),
               g, font=glyph_font, fill=col + (255,))

    # bottom label "CRYPTEX LAB"
    label_font = find_font(
        [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        ],
        size=int(s * 0.052),
    )
    label = "CRYPTEX LAB"
    spaced = " ".join(label)  # poor-man's letter-spacing
    bbox = d.textbbox((0, 0), spaced, font=label_font)
    lw = bbox[2] - bbox[0]
    d.text((cx - lw // 2 - bbox[0], int(s * 0.74)),
           spaced, font=label_font, fill=CYAN + (220,))

    # top status pip
    pip_r = max(4, s // 80)
    d.ellipse((cx - pip_r, int(s * 0.16) - pip_r,
               cx + pip_r, int(s * 0.16) + pip_r),
              fill=GREEN + (255,))
    d.ellipse((cx - pip_r * 2, int(s * 0.16) - pip_r * 2,
               cx + pip_r * 2, int(s * 0.16) + pip_r * 2),
              outline=GREEN + (110,), width=2)

    # final glow pass on cyan strokes
    glow = img.filter(ImageFilter.GaussianBlur(radius=2))
    img = Image.alpha_composite(glow, img)
    return img


def main() -> None:
    big = draw_icon(SIZE)
    big.save(OUT / "icon@512.png")
    big.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
    big.resize((64, 64), Image.LANCZOS).save(OUT / "icon-64.png")
    print(f"wrote {OUT/'icon.png'} (256x256), {OUT/'icon-64.png'} (64x64), "
          f"{OUT/'icon@512.png'} (512x512)")


if __name__ == "__main__":
    main()
