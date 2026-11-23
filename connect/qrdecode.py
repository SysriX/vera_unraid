"""QR code reader for VERA-Connect – standard library only (no zbar/OpenCV on the computers).

    decode_file(path)  -> str      image file (PNG, JPEG, BMP, GIF, TIFF – loaded with Windows GDI+) -> text of the QR code
    decode_gray(w, h, gray) -> str 8-bit grey values, row by row

Pipeline: grey image -> black/white (global Otsu, then local mean) -> three finder patterns -> version from their
distance -> alignment pattern (perspective) -> sample the module grid -> format info -> unmask -> codewords ->
Reed-Solomon error correction -> segments (numeric, alphanumeric, byte, ECI). Kanji is not needed for WireGuard.
Works for screenshots, exported PNGs and reasonably straight photos; rotated codes are fine, mirrored ones are not.
"""
from __future__ import annotations

import ctypes
import itertools
import os


class QRError(Exception):
    pass


# ------------------------------------------------------------------ image loading (GDI+)
class _GdiplusStartupInput(ctypes.Structure):
    _fields_ = [("GdiplusVersion", ctypes.c_uint32), ("DebugEventCallback", ctypes.c_void_p),
                ("SuppressBackgroundThread", ctypes.c_int), ("SuppressExternalCodecs", ctypes.c_int)]


class _BitmapData(ctypes.Structure):
    _fields_ = [("Width", ctypes.c_uint), ("Height", ctypes.c_uint), ("Stride", ctypes.c_int), ("PixelFormat", ctypes.c_int),
                ("Scan0", ctypes.c_void_p), ("Reserved", ctypes.c_size_t)]


class _GpRect(ctypes.Structure):
    _fields_ = [("X", ctypes.c_int), ("Y", ctypes.c_int), ("Width", ctypes.c_int), ("Height", ctypes.c_int)]


PIXEL_32ARGB = 0x26200A
MAX_SIDE = 1600


def load_gray(path: str, max_side: int = MAX_SIDE) -> tuple[int, int, bytes]:
    """(width, height, grey bytes). Transparent pixels count as white. Large photos are scaled down by GDI+."""
    if os.name != "nt":
        from PIL import Image                                       # only for tests outside Windows
        im = Image.open(path).convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        im = Image.alpha_composite(bg, im).convert("L")
        if max(im.size) > max_side:
            f = max_side / max(im.size)
            im = im.resize((max(1, int(im.width * f)), max(1, int(im.height * f))))
        return im.width, im.height, im.tobytes()
    if not os.path.isfile(path):
        raise QRError(f"Datei nicht gefunden: {path}")
    g = ctypes.WinDLL("gdiplus")
    token = ctypes.c_size_t()
    si = _GdiplusStartupInput(1, None, 0, 0)
    if g.GdiplusStartup(ctypes.byref(token), ctypes.byref(si), None) != 0:
        raise QRError("GDI+ nicht verfügbar")
    img, small, gfx = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if g.GdipCreateBitmapFromFile(ctypes.c_wchar_p(os.path.abspath(path)), ctypes.byref(img)) != 0:
            raise QRError("Das Bild lässt sich nicht öffnen (PNG, JPEG, BMP, GIF oder TIFF)")
        w, h = ctypes.c_uint(), ctypes.c_uint()
        g.GdipGetImageWidth(img, ctypes.byref(w))
        g.GdipGetImageHeight(img, ctypes.byref(h))
        W, H = w.value, h.value
        src = img
        if max(W, H) > max_side:                                   # scale down: drawing into a smaller bitmap
            f = max_side / max(W, H)
            W, H = max(1, int(W * f)), max(1, int(H * f))
            if g.GdipCreateBitmapFromScan0(W, H, 0, PIXEL_32ARGB, None, ctypes.byref(small)) != 0:
                raise QRError("Bild zu groß")
            g.GdipGetImageGraphicsContext(small, ctypes.byref(gfx))
            g.GdipSetInterpolationMode(gfx, 7)                      # high quality bicubic
            g.GdipGraphicsClear(gfx, ctypes.c_uint32(0xFFFFFFFF))
            g.GdipDrawImageRectI(gfx, img, 0, 0, W, H)
            g.GdipDeleteGraphics(gfx)
            src = small
        rect, bd = _GpRect(0, 0, W, H), _BitmapData()
        if g.GdipBitmapLockBits(src, ctypes.byref(rect), 1, PIXEL_32ARGB, ctypes.byref(bd)) != 0:
            raise QRError("Bildpunkte nicht lesbar")
        try:
            out = bytearray(W * H)
            for y in range(H):
                row = ctypes.string_at(bd.Scan0 + y * bd.Stride, W * 4)
                b, gr, r, a = row[0::4], row[1::4], row[2::4], row[3::4]
                o = y * W
                for x in range(W):
                    al = a[x]
                    lum = (r[x] * 299 + gr[x] * 587 + b[x] * 114) // 1000
                    out[o + x] = lum if al == 255 else (lum * al + 255 * (255 - al)) // 255
        finally:
            g.GdipBitmapUnlockBits(src, ctypes.byref(bd))
        return W, H, bytes(out)
    finally:
        if small:
            g.GdipDisposeImage(small)
        if img:
            g.GdipDisposeImage(img)
        g.GdiplusShutdown(token)


# ------------------------------------------------------------------ black/white
def _otsu(gray: bytes) -> int:
    hist = [0] * 256
    for v in gray:
        hist[v] += 1
    total, sum_all = len(gray), sum(i * c for i, c in enumerate(hist))
    wb = sb = 0
    best, thr = -1.0, 128
    for t in range(256):
        wb += hist[t]
        if not wb:
            continue
        wf = total - wb
        if not wf:
            break
        sb += t * hist[t]
        mb, mf = sb / wb, (sum_all - sb) / wf
        var = wb * wf * (mb - mf) ** 2
        if var > best:
            best, thr = var, t
    return thr


def binarize_global(w: int, h: int, gray: bytes) -> list[bytes]:
    t = _otsu(gray)
    table = bytes(1 if i <= t else 0 for i in range(256))
    return [gray[y * w:(y + 1) * w].translate(table) for y in range(h)]


def binarize_local(w: int, h: int, gray: bytes) -> list[bytes]:
    """Dark = darker than the mean of the surrounding window (copes with shadows and uneven light in photos)."""
    r = max(8, min(w, h) // 16)
    integ = [[0] * (w + 1) for _ in range(h + 1)]
    for y in range(h):
        acc, row, prev, cur = 0, gray[y * w:(y + 1) * w], integ[y], integ[y + 1]
        for x in range(w):
            acc += row[x]
            cur[x + 1] = prev[x + 1] + acc
    out = []
    for y in range(h):
        y0, y1 = max(0, y - r), min(h, y + r + 1)
        a, b = integ[y0], integ[y1]
        row = gray[y * w:(y + 1) * w]
        line = bytearray(w)
        for x in range(w):
            x0, x1 = max(0, x - r), min(w, x + r + 1)
            mean = (b[x1] - b[x0] - a[x1] + a[x0]) / ((x1 - x0) * (y1 - y0))
            line[x] = 1 if row[x] < mean - 6 else 0
        out.append(bytes(line))
    return out


# ------------------------------------------------------------------ finder patterns
def _ratio(c, pattern=(1, 1, 3, 1, 1), tol=0.6) -> float | None:
    total = sum(c)
    unit = total / sum(pattern)
    if unit < 1:
        return None
    for n, p in zip(c, pattern):
        if abs(n - unit * p) > unit * p * tol + 0.5:
            return None
    return unit


def _line_check(img, x, y, dx, dy, max_run, pattern=(1, 1, 3, 1, 1)):
    """Runs through (x, y) along (dx, dy): returns (offset of the centre, module size) or None."""
    h, w = len(img), len(img[0])

    def px(i):
        xx, yy = int(x + dx * i), int(y + dy * i)
        return img[yy][xx] if 0 <= xx < w and 0 <= yy < h else None

    if px(0) != 1:
        return None
    c = [0] * 5
    i = 0
    while px(-i) == 1 and c[2] <= max_run:
        c[2] += 1
        i += 1
    while px(-i) == 0 and c[1] <= max_run:
        c[1] += 1
        i += 1
    if px(-i) is None or c[1] > max_run:
        return None
    while px(-i) == 1 and c[0] <= max_run:
        c[0] += 1
        i += 1
    if c[0] > max_run:
        return None
    i = 1
    while px(i) == 1 and c[2] <= max_run:
        c[2] += 1
        i += 1
    while px(i) == 0 and c[3] <= max_run:
        c[3] += 1
        i += 1
    if px(i) is None or c[3] > max_run:
        return None
    while px(i) == 1 and c[4] <= max_run:
        c[4] += 1
        i += 1
    if c[4] > max_run:
        return None
    unit = _ratio(c, pattern)
    if unit is None:
        return None
    centre = i - c[4] - c[3] - c[2] / 2
    return centre, unit


def _runs(row: bytes):
    pos = 0
    out = []
    for v, grp in itertools.groupby(row):
        n = sum(1 for _ in grp)
        out.append((v, pos, n))
        pos += n
    return out


def find_finders(img) -> list[tuple[float, float, float, int]]:
    """Candidates (x, y, module size, hits)."""
    h = len(img)
    step = 1 if h < 300 else 2
    cands: list[list] = []
    for y in range(0, h, step):
        runs = _runs(img[y])
        for k in range(len(runs) - 4):
            if runs[k][0] != 1:
                continue
            c = [runs[k + j][2] for j in range(5)]
            unit = _ratio(c)
            if unit is None:
                continue
            cx = runs[k + 2][1] + runs[k + 2][2] / 2
            max_run = int(unit * 5) + 2
            v = _line_check(img, int(cx), y, 0, 1, max_run)
            if not v:
                continue
            cy = y + v[0]                                               # continuous coordinates (pixel k = [k, k+1))
            hz = _line_check(img, int(cx), int(cy), 1, 0, max_run)
            if not hz:
                continue
            cx2 = int(cx) + hz[0]
            d = _line_check(img, int(cx2), int(cy), 1, 1, max_run)          # diagonal: removes many false hits
            if not d:
                continue
            ms = (v[1] + hz[1]) / 2
            for cnd in cands:
                if abs(cnd[0] - cx2) <= ms and abs(cnd[1] - cy) <= ms and abs(cnd[2] - ms) <= max(1.0, ms * 0.5):
                    n = cnd[3]
                    cnd[0], cnd[1], cnd[2], cnd[3] = (cnd[0] * n + cx2) / (n + 1), (cnd[1] * n + cy) / (n + 1), (cnd[2] * n + ms) / (n + 1), n + 1
                    break
            else:
                cands.append([cx2, cy, ms, 1])
    return [tuple(c) for c in cands]


def _dist(a, b) -> float:
    return ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2) ** 0.5


def pick_three(cands):
    """Best triple of finder patterns: similar size, right angle, two equal legs. Ordered (top-left, top-right, bottom-left)."""
    cands = sorted(cands, key=lambda c: -c[3])[:12]
    best, best_score = None, None
    for tri in itertools.combinations(cands, 3):
        ms = [t[2] for t in tri]
        if max(ms) > 1.5 * min(ms):
            continue
        a, b, c = tri
        sides = sorted([(_dist(b, c), a), (_dist(a, c), b), (_dist(a, b), c)], key=lambda s: s[0])
        (s1, _), (s2, _), (s3, corner) = sides
        if s1 < 7 * min(ms) or s2 > 1.25 * s1:
            continue
        hyp = (s1 * s1 + s2 * s2) ** 0.5
        err = abs(s3 - hyp) / hyp
        if err > 0.15:
            continue
        score = err + (s2 / s1 - 1) + (max(ms) / min(ms) - 1) - 0.02 * sum(t[3] for t in tri)
        if best_score is None or score < best_score:
            others = [t for t in tri if t is not corner]
            best, best_score = (corner, others[0], others[1]), score
    if not best:
        raise QRError("Kein QR-Code im Bild gefunden")
    tl, p, q = best
    cross = (p[0] - tl[0]) * (q[1] - tl[1]) - (p[1] - tl[1]) * (q[0] - tl[0])
    return (tl, p, q) if cross > 0 else (tl, q, p)


# ------------------------------------------------------------------ geometry
def _solve(a, b):
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[piv][col]) < 1e-12:
            raise QRError("Bildgeometrie nicht lösbar")
        m[col], m[piv] = m[piv], m[col]
        for r in range(n):
            if r != col:
                f = m[r][col] / m[col][col]
                for k in range(col, n + 1):
                    m[r][k] -= f * m[col][k]
    return [m[i][n] / m[i][i] for i in range(n)]


def homography(src, dst):
    """3x3 matrix (as function) mapping the 4 points src -> dst."""
    a, b = [], []
    for (u, v), (x, y) in zip(src, dst):
        a.append([u, v, 1, 0, 0, 0, -u * x, -v * x])
        b.append(x)
        a.append([0, 0, 0, u, v, 1, -u * y, -v * y])
        b.append(y)
    h = _solve(a, b)

    def f(u, v):
        d = h[6] * u + h[7] * v + 1
        return (h[0] * u + h[1] * v + h[2]) / d, (h[3] * u + h[4] * v + h[5]) / d
    return f


def affine(tl, tr, bl, dim):
    s = dim - 7

    def f(u, v):
        fu, fv = (u - 3.5) / s, (v - 3.5) / s
        return (tl[0] + (tr[0] - tl[0]) * fu + (bl[0] - tl[0]) * fv, tl[1] + (tr[1] - tl[1]) * fu + (bl[1] - tl[1]) * fv)
    return f


def find_alignment(img, est, ms) -> list[tuple[float, float]]:
    """Candidates for the alignment pattern (1:1:1:1:1 around a dark centre in both directions), nearest to est first."""
    h, w = len(img), len(img[0])
    found: list[tuple[float, float]] = []
    for allowance in (5, 10, 16):
        r = int(allowance * ms)
        x0, x1 = max(0, int(est[0] - r)), min(w, int(est[0] + r))
        for y in range(max(0, int(est[1] - r)), min(h, int(est[1] + r))):
            runs = _runs(img[y][x0:x1])
            for k in range(len(runs) - 4):
                if runs[k][0] != 1:
                    continue
                c = [runs[k + j][2] for j in range(5)]
                if _ratio(c, (1, 1, 1, 1, 1), 0.7) is None or abs(sum(c) / 5 - ms) > ms * 0.7:
                    continue
                cx = x0 + runs[k + 2][1] + runs[k + 2][2] / 2
                v = _line_check(img, int(cx), y, 0, 1, int(ms * 3) + 2, (1, 1, 1, 1, 1))
                if not v:
                    continue
                cy = y + v[0]
                hz = _line_check(img, int(cx), int(cy), 1, 0, int(ms * 3) + 2, (1, 1, 1, 1, 1))
                if not hz:
                    continue
                p = (int(cx) + hz[0], cy)
                if all(_dist(p, f) > ms for f in found):
                    found.append(p)
        if found:
            break
    return sorted(found, key=lambda p: _dist(p, est))[:6]


# ------------------------------------------------------------------ QR tables
EC_PER_BLOCK = {  # level -> per version
    "L": (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "M": (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    "Q": (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    "H": (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30)}
NUM_BLOCKS = {
    "L": (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    "M": (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    "Q": (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    "H": (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81)}
LEVEL_BITS = {1: "L", 0: "M", 3: "Q", 2: "H"}


def alignment_positions(ver: int) -> list[int]:
    if ver == 1:
        return []
    size = ver * 4 + 17
    n = ver // 7 + 2
    step = (ver * 8 + n * 3 + 5) // (n * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(n - 1))


def raw_modules(ver: int) -> int:
    r = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        r -= (25 * n - 10) * n - 55
        if ver >= 7:
            r -= 36
    return r


def _format_code(level_bits: int, mask: int) -> int:
    data = level_bits << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return (data << 10 | rem) ^ 0x5412


FORMATS = {_format_code(lb, m): (lb, m) for lb in range(4) for m in range(8)}


def _version_code(ver: int) -> int:
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return ver << 12 | rem


VERSIONS = {_version_code(v): v for v in range(7, 41)}


def _nearest(code: int, table: dict, maxdist: int):
    best, bd = None, maxdist + 1
    for k, v in table.items():
        d = bin(k ^ code).count("1")
        if d < bd:
            best, bd = v, d
    return best


def function_map(ver: int) -> list[list[bool]]:
    size = ver * 4 + 17
    f = [[False] * size for _ in range(size)]

    def mark(x, y):
        if 0 <= x < size and 0 <= y < size:
            f[y][x] = True
    for i in range(size):
        mark(6, i)
        mark(i, 6)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                mark(cx + dx, cy + dy)
    pos = alignment_positions(ver)
    last = len(pos) - 1
    for i, a in enumerate(pos):
        for j, b in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == last) or (i == last and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    mark(a + dx, b + dy)
    for i in range(9):
        mark(8, i)
        mark(i, 8)
    for i in range(8):
        mark(size - 1 - i, 8)
        mark(8, size - 1 - i)
    if ver >= 7:
        for i in range(18):
            a, b = size - 11 + i % 3, i // 3
            mark(a, b)
            mark(b, a)
    return f


MASKS = (lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
         lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
         lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0, lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0)


# ------------------------------------------------------------------ Reed-Solomon (GF(256), poly 0x11D, first root α^0)
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a, b):
    return 0 if a == 0 else _EXP[(_LOG[a] + 255 - _LOG[b]) % 255]


def _pow(a, p):
    return _EXP[(_LOG[a] * p) % 255]


def _inv(a):
    return _EXP[255 - _LOG[a]]


def _p_scale(p, x):
    return [_mul(c, x) for c in p]


def _p_add(p, q):
    r = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        r[i + len(r) - len(p)] = c
    for i, c in enumerate(q):
        r[i + len(r) - len(q)] ^= c
    return r


def _p_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j, b in enumerate(q):
        for i, a in enumerate(p):
            r[i + j] ^= _mul(a, b)
    return r


def _p_eval(p, x):
    y = p[0]
    for c in p[1:]:
        y = _mul(y, x) ^ c
    return y


def _p_div(dividend, divisor):
    out = list(dividend)
    for i in range(len(dividend) - (len(divisor) - 1)):
        coef = out[i]
        if coef:
            for j in range(1, len(divisor)):
                if divisor[j]:
                    out[i + j] ^= _mul(divisor[j], coef)
    sep = -(len(divisor) - 1)
    return out[:sep], out[sep:]


def rs_correct(msg: list[int], nsym: int) -> list[int]:
    """Corrects up to nsym/2 wrong bytes; returns the data part. Raises QRError if not correctable."""
    synd = [0] + [_p_eval(msg, _pow(2, i)) for i in range(nsym)]
    if not any(synd):
        return msg[:-nsym]
    err_loc, old_loc = [1], [1]
    shift = len(synd) - nsym
    for i in range(nsym):
        k = i + shift
        delta = synd[k]
        for j in range(1, len(err_loc)):
            delta ^= _mul(err_loc[-(j + 1)], synd[k - j])
        old_loc = old_loc + [0]
        if delta:
            if len(old_loc) > len(err_loc):
                new_loc = _p_scale(old_loc, delta)
                old_loc = _p_scale(err_loc, _inv(delta))
                err_loc = new_loc
            err_loc = _p_add(err_loc, _p_scale(old_loc, delta))
    while err_loc and err_loc[0] == 0:
        del err_loc[0]
    errs = len(err_loc) - 1
    if errs * 2 > nsym:
        raise QRError("zu viele Lesefehler")
    rev = err_loc[::-1]
    n = len(msg)
    err_pos = [n - 1 - i for i in range(n) if _p_eval(rev, _pow(2, i)) == 0]
    if len(err_pos) != errs:
        raise QRError("Lesefehler nicht korrigierbar")
    coef_pos = [n - 1 - p for p in err_pos]
    e_loc = [1]
    for i in coef_pos:
        e_loc = _p_mul(e_loc, _p_add([1], [_pow(2, i), 0]))
    _, rem = _p_div(_p_mul(synd[::-1], e_loc), [1] + [0] * len(e_loc))
    err_eval = rem[::-1]
    xs = [_pow(2, -(255 - p)) for p in coef_pos]
    out = list(msg)
    for i, xi in enumerate(xs):
        xi_inv = _inv(xi)
        prime = 1
        for j, xj in enumerate(xs):
            if j != i:
                prime = _mul(prime, 1 ^ _mul(xi_inv, xj))
        if prime == 0:
            raise QRError("Lesefehler nicht korrigierbar")
        y = _mul(xi, _p_eval(err_eval[::-1], xi_inv))
        out[err_pos[i]] ^= _div(y, prime)
    if any(_p_eval(out, _pow(2, i)) for i in range(nsym)):
        raise QRError("Lesefehler nicht korrigierbar")
    return out[:-nsym]


# ------------------------------------------------------------------ matrix -> text
def read_format(m) -> tuple[str, int]:
    size = len(m)
    a = 0
    for i in range(6):
        a |= m[i][8] << i
    a |= m[7][8] << 6 | m[8][8] << 7 | m[8][7] << 8
    for i in range(9, 15):
        a |= m[8][14 - i] << i
    b = 0
    for i in range(8):
        b |= m[8][size - 1 - i] << i
    for i in range(8, 15):
        b |= m[size - 15 + i][8] << i
    for code in (a, b):
        r = _nearest(code, FORMATS, 3)
        if r:
            return LEVEL_BITS[r[0]], r[1]
    raise QRError("Formatinformation nicht lesbar")


def read_version(m) -> int | None:
    size = len(m)
    for which in (0, 1):
        code = 0
        for i in range(18):
            a, b = size - 11 + i % 3, i // 3
            bit = m[b][a] if which == 0 else m[a][b]
            code |= bit << i
        v = _nearest(code, VERSIONS, 3)
        if v:
            return v
    return None


def decode_matrix(m) -> str:
    """m[row][col] with 1 = dark."""
    size = len(m)
    ver = (size - 17) // 4
    if size != ver * 4 + 17 or not 1 <= ver <= 40:
        raise QRError("ungültige Größe")
    level, mask = read_format(m)
    func = function_map(ver)
    mf = MASKS[mask]
    bits = []
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not func[y][x]:
                    bits.append(m[y][x] ^ (1 if mf(x, y) else 0))
        right -= 2
    raw = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits) - 7, 8)]
    total = raw_modules(ver) // 8
    raw = raw[:total]
    nb, ec = NUM_BLOCKS[level][ver], EC_PER_BLOCK[level][ver]
    short_n = nb - total % nb
    short_len = total // nb
    blocks = [[0] * (short_len + 1) for _ in range(nb)]
    k = 0
    for i in range(short_len + 1):
        for j in range(nb):
            if i != short_len - ec or j >= short_n:
                blocks[j][i] = raw[k]
                k += 1
    data = []
    for j, blk in enumerate(blocks):
        if j < short_n:
            blk = blk[:short_len - ec] + blk[short_len - ec + 1:]
        data += rs_correct(blk, ec)
    return _segments(data, ver)


ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _segments(data: list[int], ver: int) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(bits):
            raise QRError("Daten abgeschnitten")
        v = int(bits[pos:pos + n], 2) if n else 0
        pos += n
        return v
    out = bytearray()
    enc = "utf-8"
    grp = 0 if ver <= 9 else 1 if ver <= 26 else 2
    while pos + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 7:                                               # ECI
            v = take(8)
            if v & 0x80:
                v = ((v & 0x3F) << 8 | take(8)) if not v & 0x40 else ((v & 0x1F) << 16 | take(16))
            enc = {3: "latin-1", 26: "utf-8", 1: "latin-1"}.get(v, "utf-8")
        elif mode == 1:
            n = take((10, 12, 14)[grp])
            while n >= 3:
                out += f"{take(10):03d}".encode()
                n -= 3
            if n == 2:
                out += f"{take(7):02d}".encode()
            elif n == 1:
                out += f"{take(4):01d}".encode()
        elif mode == 2:
            n = take((9, 11, 13)[grp])
            while n >= 2:
                v = take(11)
                out += (ALNUM[v // 45] + ALNUM[v % 45]).encode()
                n -= 2
            if n:
                out += ALNUM[take(6)].encode()
        elif mode == 4:
            n = take((8, 16, 16)[grp])
            out += bytes(take(8) for _ in range(n))
        else:
            raise QRError(f"Datenart {mode} wird nicht unterstützt")
    try:
        return out.decode(enc)
    except UnicodeDecodeError:
        return out.decode("latin-1")


# ------------------------------------------------------------------ the whole way
def _sample(img, f, dim):
    h, w = len(img), len(img[0])
    m = []
    for r in range(dim):
        row = []
        for c in range(dim):
            x, y = f(c + 0.5, r + 0.5)
            xi, yi = int(x), int(y)
            row.append(img[yi][xi] if 0 <= xi < w and 0 <= yi < h else 0)
        m.append(row)
    return m


def _module_along(img, a, b, fallback):
    """Module size of finder a measured in the direction of b (independent of the rotation of the code)."""
    L = _dist(a, b)
    ux, uy = (b[0] - a[0]) / L, (b[1] - a[1]) / L
    sizes = []
    for p, sx, sy in ((a, ux, uy), (b, -ux, -uy)):
        r = _line_check(img, p[0], p[1], sx, sy, int(fallback * 8) + 4)
        if r:
            sizes.append(r[1])
    return sum(sizes) / len(sizes) if sizes else fallback


def decode_binary(img) -> str:
    tl, tr, bl = pick_three(find_finders(img))
    ms = (tl[2] + tr[2] + bl[2]) / 3
    d = (_dist(tl, tr) / _module_along(img, tl, tr, ms) + _dist(tl, bl) / _module_along(img, tl, bl, ms)) / 2
    ms = (_dist(tl, tr) + _dist(tl, bl)) / 2 / d
    est = int(round(d)) + 7
    dims = sorted({v * 4 + 17 for v in range(1, 41)}, key=lambda s: abs(s - est))[:3]
    last = None
    for dim in dims:
        ver = (dim - 17) // 4
        transforms = []
        if ver >= 2:
            aff = affine(tl, tr, bl, dim)
            guess = aff(dim - 6.5, dim - 6.5)
            for al in find_alignment(img, guess, ms):
                try:
                    transforms.append(homography([(3.5, 3.5), (dim - 3.5, 3.5), (3.5, dim - 3.5), (dim - 6.5, dim - 6.5)],
                                                 [tl[:2], tr[:2], bl[:2], al]))
                except QRError:
                    pass
        transforms.append(affine(tl, tr, bl, dim))
        for f in transforms:
            m = _sample(img, f, dim)
            try:
                if ver >= 7:
                    v2 = read_version(m)
                    if v2 and v2 != ver:
                        continue
                return decode_matrix(m)
            except QRError as e:
                last = e
    raise last or QRError("QR-Code nicht lesbar")


def decode_gray(w: int, h: int, gray: bytes) -> str:
    last = None
    for binz in (binarize_global, binarize_local):
        img = binz(w, h, gray)
        try:
            return decode_binary(img)
        except QRError as e:
            last = e
    raise last or QRError("QR-Code nicht lesbar")


def decode_file(path: str) -> str:
    last = None
    for side in (MAX_SIDE, 800):
        w, h, gray = load_gray(path, side)
        try:
            return decode_gray(w, h, gray)
        except QRError as e:
            last = e
        if max(w, h) <= 800:
            break
    raise last or QRError("QR-Code nicht lesbar")


if __name__ == "__main__":
    import sys
    print(decode_file(sys.argv[1]))
