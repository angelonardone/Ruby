# Ruby logo

The device shows the DistributedCryptography logo (the "DC" keys) next to the name **Ruby** in ruby red (`#E0115F`).

| File | What |
|---|---|
| `DClogo.svg` | the DistributedCryptography logo, as shipped by the wallet web app (`Resources/DClogo.svg`) |
| `DClogo_dark.svg` | the same without the white square and with the white parts in black, for the black screen |
| `DClogo_dark_1024.png` | `DClogo_dark.svg` rendered at 1024×1024 on black (headless Edge / Chrome screenshot) |
| `compose.py` | builds `splash.bmp` (198×62), `statusbar_large.bmp` (134×42) and `statusbar_small.bmp` (21×21) |

Rebuild:

```
# Lato-Black.ttf (SIL Open Font License) is in the Jade builder image: /usr/share/fonts/truetype/lato/
python compose.py <dir with DClogo_dark_1024.png and Lato-Black.ttf>
cd .. && python bmp_to_compressed_bgr565_byteswapped.py splash.bmp statusbar_large.bmp statusbar_small.bmp
```

Size limits: the splash must fit `MAX_FLASH_PICTURE_SIZE` (198 × 62 pixels, `main/display.c`); every picture is at most 255 pixels wide (1-byte width). The M5Stack Basic has no PSRAM, so keep pictures small.
