"""
Generate crisp PNG icons for PhishShield AI Chrome Extension.
Creates 16x16, 32x32, 48x48, and 128x128 icons with a glowing cyber shield.
"""

import os
import math
from PIL import Image, ImageDraw

def create_shield_icon(size: int, output_path: str):
    # Create image with RGBA
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    scale = size / 128.0
    center_x = size / 2.0
    center_y = size / 2.0
    
    # Outer circle dark cyber background
    bg_margin = int(4 * scale)
    draw.ellipse(
        [bg_margin, bg_margin, size - bg_margin, size - bg_margin],
        fill=(10, 15, 29, 255),
        outline=(0, 229, 255, 220),
        width=max(1, int(3 * scale))
    )
    
    # Shield coordinates scaled
    # Top left: 36, 32 -> Top center: 64, 24 -> Top right: 92, 32 -> 
    # Mid right: 94, 68 -> Bottom tip: 64, 102 -> Mid left: 34, 68
    shield_pts = [
        (int(center_x), int(26 * scale)),
        (int(94 * scale), int(34 * scale)),
        (int(92 * scale), int(72 * scale)),
        (int(center_x), int(104 * scale)),
        (int(36 * scale), int(72 * scale)),
        (int(34 * scale), int(34 * scale))
    ]
    
    # Shield fill (cyber blue / teal gradient look)
    draw.polygon(shield_pts, fill=(14, 116, 144, 255), outline=(6, 182, 212, 255))
    
    # Inner shield highlight
    inner_pts = [
        (int(center_x), int(32 * scale)),
        (int(86 * scale), int(39 * scale)),
        (int(84 * scale), int(68 * scale)),
        (int(center_x), int(96 * scale)),
        (int(44 * scale), int(68 * scale)),
        (int(42 * scale), int(39 * scale))
    ]
    draw.polygon(inner_pts, fill=(8, 51, 68, 255), outline=(56, 189, 248, 180))
    
    # Padlock / Checkmark in center of shield
    # Draw checkmark or lock
    if size >= 32:
        # Padlock body
        lock_w = int(22 * scale)
        lock_h = int(18 * scale)
        lock_x = int(center_x - lock_w / 2)
        lock_y = int(58 * scale)
        
        # Shackle
        shackle_r = int(7 * scale)
        draw.arc(
            [int(center_x - shackle_r), int(46 * scale), int(center_x + shackle_r), int(62 * scale)],
            start=180, end=0, fill=(240, 253, 250, 255), width=max(2, int(3 * scale))
        )
        
        # Body
        draw.rounded_rectangle(
            [lock_x, lock_y, lock_x + lock_w, lock_y + lock_h],
            radius=int(3 * scale),
            fill=(16, 185, 129, 255), # Emerald safe lock
            outline=(240, 253, 250, 255),
            width=max(1, int(1.5 * scale))
        )
        
        # Keyhole dot
        draw.ellipse(
            [int(center_x - 2 * scale), int(lock_y + 6 * scale), int(center_x + 2 * scale), int(lock_y + 10 * scale)],
            fill=(10, 15, 29, 255)
        )
    else:
        # Smaller 16x16: draw simple sharp checkmark
        draw.line(
            [(int(center_x - 3 * scale), int(center_y)), (int(center_x - 1 * scale), int(center_y + 3 * scale))],
            fill=(52, 211, 153, 255), width=2
        )
        draw.line(
            [(int(center_x - 1 * scale), int(center_y + 3 * scale)), (int(center_x + 4 * scale), int(center_y - 2 * scale))],
            fill=(52, 211, 153, 255), width=2
        )

    img.save(output_path, "PNG")
    print(f"Generated icon: {output_path} ({size}x{size})")

if __name__ == "__main__":
    icon_dir = os.path.dirname(os.path.abspath(__file__))
    for s in [16, 32, 48, 128]:
        out = os.path.join(icon_dir, f"icon{s}.png")
        create_shield_icon(s, out)

