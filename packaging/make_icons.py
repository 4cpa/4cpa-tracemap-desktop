"""Erzeugt Symbole für alle Plattformen aus static/logo.png (benötigt Pillow)."""
from pathlib import Path

from PIL import Image

root = Path(__file__).resolve().parent.parent
out = root / "packaging" / "icons"
out.mkdir(parents=True, exist_ok=True)
img = Image.open(root / "static" / "logo.png").convert("RGBA")
size = max(img.size)
canvas = Image.new("RGBA", (size, size), (255, 255, 255, 255))
canvas.paste(img, ((size - img.width) // 2, (size - img.height) // 2), img)
big = canvas.resize((512, 512), Image.LANCZOS)
big.save(out / "app.png")
big.save(out / "app.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
big.save(out / "app.icns")
print("Symbole erzeugt:", sorted(p.name for p in out.iterdir()))
