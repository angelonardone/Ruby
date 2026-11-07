import sys, os
from PIL import Image, ImageFont, ImageDraw
S = sys.argv[1]
RUBY = (0xE0, 0x11, 0x5F)
src = Image.open(os.path.join(S, "DClogo_dark_1024.png")).convert("RGB")
bbox = src.point(lambda v: 255 if v > 24 else 0).convert("L").getbbox()
icon = src.crop(bbox)
side = max(icon.size)
sq = Image.new("RGB", (side, side), (0, 0, 0)); sq.paste(icon, ((side - icon.size[0]) // 2, (side - icon.size[1]) // 2))
def ic(n): return sq.resize((n, n), Image.LANCZOS)
def text_img(txt, h, font):
    good = None
    for size in range(10, 200):
        f = ImageFont.truetype(os.path.join(S, font), size)
        b = f.getbbox(txt)
        if b[3] - b[1] > h: break
        good = f
    b = good.getbbox(txt)
    im = Image.new("RGB", (b[2] - b[0] + 2, b[3] - b[1] + 2), (0, 0, 0))
    ImageDraw.Draw(im).text((-b[0] + 1, -b[1] + 1), txt, font=good, fill=RUBY)
    return im
def compose(w, h, icon_px, text_h, gap):
    out = Image.new("RGB", (w, h), (0, 0, 0))
    t = text_img("Ruby", text_h, "Lato-Black.ttf")
    total = icon_px + gap + t.size[0]
    assert total <= w, (total, w)
    x0 = (w - total) // 2
    out.paste(ic(icon_px), (x0, (h - icon_px) // 2))
    out.paste(t, (x0 + icon_px + gap, (h - t.size[1]) // 2))
    return out
compose(134, 42, 40, 30, 6).save(os.path.join(S, "statusbar_large.bmp"))
ic(21).save(os.path.join(S, "statusbar_small.bmp"))
compose(198, 62, 58, 40, 8).save(os.path.join(S, "splash.bmp"))
for n, z in [("statusbar_large", 4), ("statusbar_small", 6), ("splash", 3)]:
    im = Image.open(os.path.join(S, n + ".bmp")); print(n, im.size)
    im.resize((im.size[0] * z, im.size[1] * z), Image.NEAREST).save(os.path.join(S, "preview_" + n + ".png"))
