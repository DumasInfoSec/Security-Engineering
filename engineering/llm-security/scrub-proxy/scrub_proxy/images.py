"""Image scrubbing: OCR -> same detectors as text -> black boxes labelled with placeholders.

Re-encoding also drops EXIF (GPS, device, timestamps). Each box carries its placeholder in
white text so the model can refer to the value and restore maps it back in responses.
"""
import base64
import hashlib
import io
import math
import re
import os

from PIL import Image, ImageDraw, ImageFont, ImageOps

from .scrubber import BlockedContent
from .store import PH_RE

OCR_MAX_SIDE = int(os.environ.get("SCRUB_OCR_MAX_SIDE", "3000"))
FUZZY_MIN_LEN = 6
FUZZY_CUTOFF = 88  # rapidfuzz partial_ratio, tolerates OCR misreads like O/0, l/1
_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
# OCR drops or swaps quotes, which defeats detect-secrets' keyword rule; this one is lenient.
OCR_KEYWORD = re.compile(
    r"(?i)(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_ -]?key|access[_ -]?key|private[_ -]?key"
    r"|client[_ -]?secret|auth|credential|pin)\w*\s*[:=]\s*[\"'`‘’“”]?([^\s\"'`‘’“”,;(){}]{4,})")
SUPPORTED = {"image/png", "image/jpeg", "image/webp", "image/gif"}


class ImageError(BlockedContent):
    pass


def _font(size: int):
    try:
        return ImageFont.truetype(_FONT, size)
    except OSError:
        return ImageFont.load_default(size=size)


class ImageScrubber:
    def __init__(self, store=None):  # store comes from the Scrubber at call time
        from rapidocr_onnxruntime import RapidOCR
        self.ocr = RapidOCR()

    # ------------------------------------------------------------ decode + OCR
    @staticmethod
    def decode(b64: str, media_type: str) -> Image.Image:
        if media_type not in SUPPORTED:
            raise ImageError(f"unsupported image type {media_type}")
        try:
            im = Image.open(io.BytesIO(base64.b64decode(b64, validate=False)))
            im.seek(0)  # animated GIF/WebP: first frame only is forwarded
            im = ImageOps.exif_transpose(im)
            if im.mode in ("RGBA", "LA", "P"):
                im = im.convert("RGBA")
                bg = Image.new("RGB", im.size, (255, 255, 255))
                bg.paste(im, mask=im.split()[-1])
                im = bg
            return im.convert("RGB")
        except Exception as e:
            raise ImageError(f"cannot decode image: {e}") from e

    def lines(self, store, im: Image.Image, digest: str) -> list[dict]:
        """OCR lines: {text, quad, chars:[quad per char] | None}; quads are [tl, tr, br, bl]
        in original pixel coords."""
        key = f"ocr:v2:{digest}"
        cached = store.cache_get(key)
        if cached is not None:
            return cached
        scale = min(1.0, OCR_MAX_SIDE / max(im.size))
        src = im if scale == 1.0 else im.resize(
            (round(im.width * scale), round(im.height * scale)), Image.LANCZOS)
        import numpy as np
        res, _ = self.ocr(np.asarray(src), return_word_box=True)
        out = []
        for r in res or []:
            quad, text = r[0], r[1]
            chars = None
            if len(r) >= 5 and len(r[4]) == len(text) and len(r[3]) == len(text):
                chars = [[[x / scale, y / scale] for x, y in q] for q in r[3]]
            out.append({"text": text, "quad": [[x / scale, y / scale] for x, y in quad],
                        "chars": chars})
        store.cache_set(key, out)
        return out

    @staticmethod
    def _bbox(quad, scale=1.0):
        xs = [p[0] / scale for p in quad]
        ys = [p[1] / scale for p in quad]
        return [min(xs), min(ys), max(xs), max(ys)]

    # ------------------------------------------------------------ span finding
    def fuzzy_known(self, store, text: str) -> list:
        from rapidfuzz import fuzz
        out = []
        low = text.lower()
        for v, ph in list(store.by_val.items()):
            if len(v) < FUZZY_MIN_LEN or len(v) > len(text) + 4:
                continue
            a = fuzz.partial_ratio_alignment(v.lower(), low, score_cutoff=FUZZY_CUTOFF)
            if a and a.dest_end > a.dest_start:
                out.append((a.dest_start, a.dest_end, ph.split("_")[0], store.types[v], ph))
        return out

    @staticmethod
    def poly(line: dict, s: int, e: int, pad: float = 0.2):
        """Quadrilateral covering chars [s, e) that follows the text slant, padded."""
        if line["chars"]:
            tl, bl = line["chars"][s][0], line["chars"][s][3]
            tr, br = line["chars"][e - 1][1], line["chars"][e - 1][2]
        else:  # no char boxes: proportional slice of the line quad, one extra char each side
            q, n = line["quad"], max(len(line["text"]), 1)
            f0, f1 = max(0.0, (s - 1) / n), min(1.0, (e + 1) / n)
            lerp = lambda a, b, f: [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f]
            tl, tr, bl, br = lerp(q[0], q[1], f0), lerp(q[0], q[1], f1), lerp(q[3], q[2], f0), lerp(q[3], q[2], f1)
        ux, uy = tr[0] - tl[0], tr[1] - tl[1]
        ul = math.hypot(ux, uy) or 1.0
        ux, uy = ux / ul, uy / ul
        vx, vy = bl[0] - tl[0], bl[1] - tl[1]
        h = math.hypot(vx, vy) or 1.0
        vx, vy = vx / h, vy / h
        p = pad * h
        pts = [(tl, -1, -1), (tr, 1, -1), (br, 1, 1), (bl, -1, 1)]
        quad = [(x + a * p * ux + b * p * vx, y + a * p * uy + b * p * vy) for (x, y), a, b in pts]
        return quad, ul + 2 * p, h + 2 * p, math.degrees(math.atan2(uy, ux))

    @staticmethod
    def _merge(text: str, spans: list) -> list:
        """Union overlapping spans; keep a span's own placeholder only if it covers the union."""
        spans = sorted(spans, key=lambda x: (x[0], -x[1]))
        merged = []
        for s, e, kind, typ, ph in spans:
            if merged and s < merged[-1][1]:
                cur = merged[-1]
                if e > cur[1]:
                    cur[1], cur[4] = e, None
                if kind == "SEC" and cur[2] == "PII":
                    cur[2], cur[3] = kind, typ
            else:
                merged.append([s, e, kind, typ, ph])
        return merged

    def _label(self, im, quad, w, h, angle, ph):
        size = int(min(h * 0.55, w / (0.62 * len(ph))))
        if size < 7:
            return
        lab = Image.new("RGBA", (max(int(w), 1), max(int(h), 1)), (0, 0, 0, 0))
        ImageDraw.Draw(lab).text((h * 0.15, (h - size) / 2 - size * 0.1), ph,
                                 font=_font(size), fill=(255, 255, 255, 255))
        lab = lab.rotate(-angle, resample=Image.BICUBIC, expand=True)
        cx = sum(p[0] for p in quad) / 4
        cy = sum(p[1] for p in quad) / 4
        im.paste(lab, (round(cx - lab.width / 2), round(cy - lab.height / 2)), lab)

    # ------------------------------------------------------------ main entry
    def scrub_block(self, block: dict, scrubber, stats) -> dict:
        """Mutates an image block in place; returns it."""
        src = block["source"]
        raw_b64 = src["data"]
        digest = hashlib.sha256(raw_b64.encode()).hexdigest()
        im = self.decode(raw_b64, src.get("media_type", "image/png"))
        st = scrubber.store
        lines = self.lines(st, im, digest)

        # one joined text gives NER and multi-line regexes context; map offsets back to lines
        joined, starts = [], []
        pos = 0
        for ln in lines:
            starts.append(pos)
            joined.append(ln["text"])
            pos += len(ln["text"]) + 1
        text = "\n".join(joined)
        spans = [tuple(s) for s in scrubber.detect([text])[0]]
        spans += [(m.start(1), m.end(1), "SEC", "OCRKEYWORD") for m in OCR_KEYWORD.finditer(text)
                  if not PH_RE.search(m.group(1))]
        for s, e, kind, typ in spans:  # register so later text mentions are scrubbed too
            v = text[s:e]
            if e > s and v not in scrubber.allow and not PH_RE.search(v):
                st.placeholder_for(kind, typ, v)
        spans = [(*sp, None) for sp in spans + scrubber._known_spans(text)]
        for i, ln in enumerate(lines):
            spans += [(starts[i] + s, starts[i] + e, k, t, ph)
                      for s, e, k, t, ph in self.fuzzy_known(st, ln["text"])]

        spans = [sp for sp in spans if text[sp[0]:sp[1]].strip() and text[sp[0]:sp[1]] not in scrubber.allow]
        regions = []
        for s, e, kind, typ, ph in self._merge(text, spans):
            v = text[s:e]
            ph = ph or st.by_val.get(v) or st.placeholder_for(kind, typ, v)
            for i, ln in enumerate(lines):
                ls, le = starts[i], starts[i] + len(ln["text"])
                a, b = max(s, ls), min(e, le)
                if a < b:
                    regions.append((self.poly(ln, a - ls, b - ls), ph))
            stats[f"IMG_{typ}"] += 1

        # always re-encode: strips EXIF/GPS even when nothing was found
        draw = ImageDraw.Draw(im)
        for (quad, _, _, _), _ in regions:  # all boxes first, so no label gets painted over
            draw.polygon(quad, fill=(0, 0, 0))
        for (quad, w, h, angle), ph in regions:
            self._label(im, quad, w, h, angle, ph)
        buf = io.BytesIO()
        if src.get("media_type") == "image/jpeg":
            im.save(buf, "JPEG", quality=90)
        else:
            im.save(buf, "PNG", optimize=False)
            src["media_type"] = "image/png"
        src["data"] = base64.b64encode(buf.getvalue()).decode()
        return block
